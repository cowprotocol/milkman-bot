use anyhow::{Context, Result};
use ethers::prelude::*;
use hex::FromHex;
use log::debug;
#[cfg(test)]
use rand::prelude::*;
use std::convert::{From, Into};
use std::sync::Arc;

use crate::configuration::Configuration;
use crate::constants::{APP_DATA, ERC20_BALANCE, KIND_SELL};
use crate::encoder::{self, SignatureData};
use crate::types::{BlockNumber, Swap};

abigen!(
    RawMilkman,
    "./abis/Milkman.json",
    event_derives(serde::Deserialize, serde::Serialize),
);

abigen!(
    RawHashHelper,
    "./abis/HashHelper.json",
    event_derives(serde::Deserialize, serde::Serialize),
);

abigen!(
    RawERC20,
    "./abis/ERC20.json",
    event_derives(serde::Deserialize, serde::Serialize),
);

pub type Milkman = RawMilkman<Provider<Http>>;
pub type HashHelper = RawHashHelper<Provider<Http>>;
pub type ERC20 = RawERC20<Provider<Http>>;

pub struct EthereumClient {
    inner_client: Arc<Provider<Http>>,
    milkman: Milkman,
}

impl EthereumClient {
    pub fn new(config: &Configuration) -> Result<Self> {
        let node_url = if config.node_base_url.is_some() {
            config.node_base_url.clone().unwrap()
        } else {
            format!(
                "https://{}.infura.io/v3/{}",
                config.network,
                config.infura_api_key.clone().unwrap()
            )
        };
        let provider = Arc::new(Provider::<Http>::try_from(node_url)?);

        Ok(Self {
            milkman: Milkman::new(config.milkman_address, Arc::clone(&provider)),
            inner_client: provider,
        })
    }

    pub async fn get_latest_block_number(&self) -> Result<u64> {
        self.get_latest_block()
            .await?
            .number
            .context("Error extracting number from latest block.")
            .map(|block_num: U64| block_num.try_into().unwrap()) // U64 -> u64 should always work
    }

    #[cfg(test)]
    pub async fn get_chain_id(&self) -> Result<u64> {
        Ok(self.inner_client.get_chainid().await?.as_u64())
    }

    #[cfg(test)]
    pub async fn impersonate(&self, address: &H160) -> Result<(), ProviderError> {
        self.inner_client
            .request("anvil_impersonateAccount", [address])
            .await
    }

    #[cfg(test)]
    pub async fn mine_empty_block(&self) -> Result<(), ProviderError> {
        self.inner_client.request("anvil_mine", [1]).await
    }

    async fn get_latest_block(&self) -> Result<Block<H256>> {
        self.inner_client
            .get_block(ethers::core::types::BlockNumber::Latest)
            .await?
            .context("Error fetching latest block.")
    }

    pub async fn get_requested_swaps(
        &self,
        from_block: BlockNumber,
        to_block: BlockNumber,
    ) -> Result<Vec<Swap>> {
        Ok(self
            .milkman
            .swap_requested_filter()
            .from_block(from_block)
            .to_block(to_block)
            .query()
            .await?
            .iter()
            .map(Into::into)
            .collect())
    }

    pub async fn get_balance_of(&self, token_address: Address, user: Address) -> Result<U256> {
        let token = ERC20::new(token_address, Arc::clone(&self.inner_client));

        Ok(token.balance_of(user).call().await?)
    }

    /// To estimate the amount of gas it'll take to call `isValidSignature`, we
    /// create a mock order & signature based on the existing order and use those
    /// along with ethers-rs's `estimate_gas()`.
    pub async fn get_estimated_order_contract_gas(
        &self,
        config: &Configuration,
        swap_request: &Swap,
    ) -> Result<U256> {
        let order_contract =
            Milkman::new(swap_request.order_contract, Arc::clone(&self.inner_client));

        let hash_helper =
            HashHelper::new(config.hash_helper_address, Arc::clone(&self.inner_client));

        let domain_separator = self.milkman.domain_separator().call().await?;

        let mock_order = Data {
            sell_token: swap_request.from_token,
            buy_token: swap_request.to_token,
            receiver: swap_request.receiver,
            sell_amount: swap_request.amount_in,
            buy_amount: U256::MAX,
            valid_to: u32::MAX,
            app_data: Vec::from_hex(APP_DATA).unwrap().try_into().unwrap(),
            fee_amount: U256::zero(),
            kind: Vec::from_hex(KIND_SELL).unwrap().try_into().unwrap(),
            partially_fillable: false,
            sell_token_balance: Vec::from_hex(ERC20_BALANCE).unwrap().try_into().unwrap(),
            buy_token_balance: Vec::from_hex(ERC20_BALANCE).unwrap().try_into().unwrap(),
        };

        let mock_order_digest = hash_helper
            .hash(mock_order, domain_separator)
            .call()
            .await?;

        let mock_signature = encoder::get_eip_1271_signature(SignatureData {
            from_token: swap_request.from_token,
            to_token: swap_request.to_token,
            receiver: swap_request.receiver,
            sell_amount_after_fees: swap_request.amount_in,
            buy_amount_after_fees_and_slippage: U256::MAX,
            valid_to: u32::MAX as u64,
            fee_amount: U256::zero(),
            order_creator: swap_request.order_creator,
            price_checker: swap_request.price_checker,
            price_checker_data: &swap_request.price_checker_data,
        });

        debug!(
            "isValidSignature({:?},{:?})",
            hex::encode(mock_order_digest),
            hex::encode(&mock_signature.0)
        );
        debug!(
            "Is valid sig? {:?}",
            order_contract
                .is_valid_signature(mock_order_digest, mock_signature.clone())
                .call()
                .await?
        );

        Ok(order_contract
            .is_valid_signature(mock_order_digest, mock_signature)
            .estimate_gas()
            .await?)
    }
}

impl From<&SwapRequestedFilter> for Swap {
    fn from(raw_swap_request: &SwapRequestedFilter) -> Self {
        Self {
            order_contract: raw_swap_request.order_contract,
            order_creator: raw_swap_request.order_creator,
            receiver: raw_swap_request.to,
            from_token: raw_swap_request.from_token,
            to_token: raw_swap_request.to_token,
            amount_in: raw_swap_request.amount_in,
            price_checker: raw_swap_request.price_checker,
            price_checker_data: raw_swap_request.price_checker_data.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ethereum_client() {
        let config = Configuration {
            infura_api_key: None,
            network: "mainnet".to_string(),
            milkman_address: "0x11C76AD590ABDFFCD980afEC9ad951B160F02797"
                .parse()
                .unwrap(),
            hash_helper_address: "0x49Fc95c908902Cf48f5F26ed5ADE284de3b55197"
                .parse()
                .unwrap(),
            starting_block_number: None,
            polling_frequency_secs: 15,
            node_base_url: Some("http://127.0.0.1:8545".into()),
            slippage_tolerance_bps: 50,
        };

        let eth_client = EthereumClient::new(&config).expect("Unable to create Ethereum client");

        let milkman = Milkman::new(config.milkman_address, Arc::clone(&eth_client.inner_client));

        let latest_block_num = eth_client
            .get_latest_block_number()
            .await
            .expect("Unable to get latest block number");
        let first_block_in_fork = latest_block_num + 1;
        let chain_id = eth_client
            .get_chain_id()
            .await
            .expect("Unable to get chain id");
        assert_eq!(chain_id, 1, "Test must be run on mainnet");
        assert_eq!(
            latest_block_num, 20920411,
            "Test is designed for a specific mainnet block"
        );

        let weth = token("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2", &eth_client);
        let dai = token("0x6B175474E89094C44Da98b954EedeAC495271d0F", &eth_client);
        // Any EOA that has a large amount of WETH at the fork block
        let weth_whale: H160 = "0x8eb8a3b98659cce290402893d0123abb75e3ab28"
            .parse()
            .unwrap();

        eth_client.impersonate(&weth_whale).await.expect(
            "Node should be able to impersonate accounts. Is the node compatible with Anvil?",
        );

        assert!(swaps_since(first_block_in_fork, &eth_client)
            .await
            .is_empty());

        weth.approve(milkman.address(), U256::max_value())
            .from(weth_whale)
            .send()
            .await
            .expect("Must be able to approve token");

        let amount_in = U256::exp10(18);
        let receiver = H160([0x42; 20]);
        let price_checker = H160([0x11; 20]);
        let price_checker_data = Bytes::from([0x13, 0x37]);
        milkman
            .request_swap_exact_tokens_for_tokens(
                amount_in,
                weth.address(),
                dai.address(),
                receiver,
                price_checker,
                price_checker_data.clone(),
            )
            .from(weth_whale)
            .send()
            .await
            .expect("Swap request must succeed");

        // Without mining an empty block, the test is flaky.
        // Sometimes, the swap events are not registered and it looks like there
        // were no swaps.
        eth_client
            .mine_empty_block()
            .await
            .expect("Must mine empty block");

        let mut swaps = swaps_since(first_block_in_fork, &eth_client).await;
        assert_eq!(swaps.len(), 1);

        let swap = swaps.pop().unwrap();
        assert_eq!(swap.amount_in, amount_in);
        assert_eq!(swap.from_token, weth.address());
        assert_eq!(swap.to_token, dai.address());
        assert_eq!(swap.receiver, receiver);
        assert_eq!(swap.price_checker, price_checker);
        assert_eq!(swap.price_checker_data, price_checker_data);
        assert_eq!(swap.order_creator, weth_whale);
    }

    fn token(address: &str, eth_client: &EthereumClient) -> ERC20 {
        let address: H160 = address.parse().expect("Not a valid address");
        ERC20::new(address, Arc::clone(&eth_client.inner_client))
    }

    async fn swaps_since(block_nr: u64, eth_client: &EthereumClient) -> Vec<Swap> {
        let latest_block_num = eth_client
            .get_latest_block_number()
            .await
            .expect("Unable to get latest block number");
        eth_client
            .get_requested_swaps(block_nr, latest_block_num)
            .await
            .expect("Unable to get requested swaps")
    }

    #[test]
    fn test_convert_swap() {
        let order_contract = Address::random();
        let order_creator = Address::random();
        let amount_in: U256 = rand::thread_rng().gen::<u128>().into();
        let from_token = Address::random();
        let to_token = Address::random();
        let to = Address::random();
        let price_checker = Address::random();
        let price_checker_data: Bytes = rand::thread_rng().gen::<[u8; 1000]>().into();

        let raw_swap = SwapRequestedFilter {
            order_contract,
            order_creator,
            amount_in,
            from_token,
            to_token,
            to,
            price_checker,
            price_checker_data: price_checker_data.clone(),
        };
        let converted: Swap = (&raw_swap).into();

        assert_eq!(converted.order_contract, order_contract);
        assert_eq!(converted.order_creator, order_creator);
        assert_eq!(converted.amount_in, amount_in);
        assert_eq!(converted.from_token, from_token);
        assert_eq!(converted.to_token, to_token);
        assert_eq!(converted.receiver, to);
        assert_eq!(converted.price_checker, price_checker);
        assert_eq!(converted.price_checker_data, price_checker_data);
    }
}
