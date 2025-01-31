use anyhow::{bail, Context, Result};
use ethers::prelude::*;
use hex::ToHex;
use std::{collections::HashMap, time::Duration};
use tokio::time::sleep;
use tracing::Instrument;

mod configuration;

use crate::configuration::Configuration;

mod ethereum_client;

use crate::ethereum_client::EthereumClient;

mod cow_api_client;

use crate::cow_api_client::{CowAPIClient, Order};

mod encoder;

use crate::encoder::SignatureData;

mod types;

use crate::types::Swap;

mod constants;

/// Every x seconds, do the following:
/// - check for new Milkman swap requests, and enqueue them into a swap queue
/// - check if items in the swap queue have already been fulfilled
///     - if the swap has already been fulfilled, dequeue it
///     - if the swap hasn't been fulfilled, create an order via the CoW API
///
/// This implies that multiple API orders can be created for a single swap request.
/// We accept this trade-off because it gives us additional simplicity, and the
/// marginal cloud compute cost to CoW is likely to be very small.
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    tracing::info!("=== MILKMAN BOT STARTING ===");

    let config = Configuration::get_from_environment()
        .expect("Unable to get configuration from the environment variables."); // .expect() because every decision to panic should be conscious, not just triggered by a `?` that we didn't think about

    let eth_client = EthereumClient::new(&config).expect("Unable to create the Ethereum client.");
    let cow_api_client = CowAPIClient::new(&config);

    // During development, I found Infura's WebSockets endpoint to sometimes miss
    // swaps, so we pull in requested swaps by quering through a series of ranges.
    // For example, if the user passes in a starting block number of 10 and the
    // current block number is 20, the initial request would pull from 10 to 20.
    // After that first request, `range_start` would be set to 20. By the time
    // of the second request, we will query the current block number, let's say
    // 22, and so query from 20 to 22. This is repeated in an infinite loop.
    let mut range_start = config.starting_block_number.unwrap_or(
        eth_client
            .get_latest_block_number()
            .await
            .expect("Unable to get latest block number before starting."),
    );

    tracing::debug!("range start: {}", range_start);

    let mut swap_queue = HashMap::new();

    loop {
        sleep(Duration::from_secs(config.polling_frequency_secs)).await;

        let range_end = eth_client
            .get_latest_block_number()
            .await
            .expect("Unable to get latest block number."); // should we panic here if we can't get it? another option would be continuing in the loop, but then we might not observe that the bot is really `down`

        tracing::debug!("range end: {}", range_end);

        // add the - 100 to cast a wider net since Infura sometimes doesn't reply
        let requested_swaps = match eth_client
            .get_requested_swaps(range_start - 100, range_end)
            .await
        {
            Ok(swaps) => swaps,
            Err(err) => {
                tracing::error!("unable to get requested swaps – {:?}", err);
                continue;
            }
        };

        if !requested_swaps.is_empty() {
            tracing::info!(
                "Found {} requested swaps between blocks {} and {}",
                requested_swaps.len(),
                range_start,
                range_end
            );
        }

        for requested_swap in requested_swaps {
            tracing::info!("Inserting following swap in queue: {:?}", requested_swap);
            tracing::debug!(
                "Price checker data hex: 0x{}",
                requested_swap.price_checker_data.encode_hex::<String>()
            );
            swap_queue.insert(requested_swap.order_contract, requested_swap);
        }

        for requested_swap in swap_queue.clone().values() {
            let is_swap_fulfilled = match is_swap_fulfilled(requested_swap, &eth_client).await {
                Ok(res) => res,
                Err(err) => {
                    tracing::error!("unable to determine if swap was fulfilled – {:?}", err);
                    continue;
                }
            };

            if is_swap_fulfilled {
                tracing::info!(
                    "Swap with order contract ({}) was fulfilled, removing from queue.",
                    requested_swap.order_contract
                );
                swap_queue.remove(&requested_swap.order_contract);
            } else {
                let contract = format!("{:#x}", requested_swap.order_contract);
                async {
                    if let Err(err) =
                        handle_swap(requested_swap, &eth_client, &cow_api_client, &config).await
                    {
                        tracing::error!("unable to handle swap {:?}", err);
                    }
                }
                .instrument(tracing::info_span!("handle_swap", contract))
                .await
            }
        }

        range_start = range_end;
    }
}

async fn handle_swap(
    requested_swap: &Swap,
    eth_client: &EthereumClient,
    cow_api_client: &CowAPIClient,
    config: &Configuration,
) -> Result<()> {
    tracing::info!(
        "Handling swap with order contract ({})",
        requested_swap.order_contract
    );
    let mut verification_gas_limit = match eth_client
        .get_estimated_order_contract_gas(config, requested_swap)
        .await
    {
        Ok(res) => res,
        Err(err) => {
            bail!("unable to estimate verification gas – {:?}", err);
        }
    };
    verification_gas_limit = (verification_gas_limit * 11) / 10; // extra padding
    tracing::debug!(
        "verification gas limit to use - {:?}",
        verification_gas_limit
    );

    let quote = match cow_api_client
        .get_quote(
            requested_swap.order_contract,
            requested_swap.from_token,
            requested_swap.to_token,
            requested_swap.amount_in,
            verification_gas_limit.as_u64(),
            requested_swap.app_data,
        )
        .await
    {
        Ok(res) => res,
        Err(err) => {
            bail!("unable to fetch quote - {:?}", err);
        }
    };

    let sell_amount_after_fees = requested_swap.amount_in;
    let buy_amount_after_fees_and_slippage =
        quote.buy_amount_after_fee * (10000 - config.slippage_tolerance_bps) / 10000;

    let eip_1271_signature = encoder::get_eip_1271_signature(SignatureData {
        from_token: requested_swap.from_token,
        to_token: requested_swap.to_token,
        receiver: requested_swap.receiver,
        sell_amount_after_fees,
        buy_amount_after_fees_and_slippage,
        valid_to: quote.valid_to,
        fee_amount: U256::zero(),
        order_creator: requested_swap.order_creator,
        app_data: requested_swap.app_data,
        price_checker: requested_swap.price_checker,
        price_checker_data: &requested_swap.price_checker_data,
    });
    tracing::debug!(signature = ?eip_1271_signature.to_string());

    cow_api_client
        .create_order(Order {
            order_contract: requested_swap.order_contract,
            sell_token: requested_swap.from_token,
            buy_token: requested_swap.to_token,
            sell_amount: sell_amount_after_fees,
            buy_amount: buy_amount_after_fees_and_slippage,
            valid_to: quote.valid_to,
            fee_amount: U256::zero(),
            receiver: requested_swap.receiver,
            app_data: requested_swap.app_data,
            eip_1271_signature: &eip_1271_signature,
            quote_id: quote.id,
        })
        .await
        .context("unable to create order via CoW API")?;
    Ok(())
}

async fn is_swap_fulfilled(swap: &Swap, eth_client: &EthereumClient) -> Result<bool> {
    // if all `from` tokens are gone, the swap must have been completed or cancelled
    Ok(eth_client
        .get_balance_of(swap.from_token, swap.order_contract)
        .await?
        .is_zero())
}
