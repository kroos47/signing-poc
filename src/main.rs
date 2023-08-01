use avail_subxt::config::Hasher;
use anyhow::Result;
use codec::Compact;
use avail_subxt::{
    api::{
        self,
        data_availability::calls::SubmitData,
        runtime_types::{
            da_control::pallet::Call as DaCall, sp_core::bounded::bounded_vec::BoundedVec,
        },
    },
    avail::AppUncheckedExtrinsic,
    build_client,
    primitives::AvailExtrinsicParams,
    AvailConfig, Call, Opts, AccountId,
};
use serde::{Deserialize, Serialize};
use sp_core::{crypto::Pair as _, Encode};
use sp_keyring::{
    sr25519::sr25519::{self, Pair},
    AccountKeyring,
};
use sp_core::crypto::Ss58Codec;

use structopt::StructOpt;
use subxt::{
    blocks::ExtrinsicEvents,
    tx::{PairSigner, StaticTxPayload, Signer, SubmittableExtrinsic},
    utils::{MultiAddress,Encoded}, config::ExtrinsicParams, Config
};

#[async_std::main]
async fn main() -> Result<()>{
    let args = Opts::from_args();
    let client = build_client(args.ws, args.validate_codegen)
        .await?;
    let signer =
        PairSigner::<AvailConfig, sp_core::sr25519::Pair>::new(AccountKeyring::Alice.pair());
        let example_data = b"example".to_vec();
        let data_transfer = api::tx()
        .data_availability()
        .submit_data(BoundedVec(example_data.clone()));
    client.tx().validate(&data_transfer)?;
    let nonce = client.rpc().system_account_next_index(signer.account_id()).await?;
	let extrinsic_params = AvailExtrinsicParams::new_with_app_id(1.into());
    // let encoded_call_data = data_transfer.call_data();
    let call_data = client.tx().call_data(&data_transfer)?;
    let encoded_call_data = Encoded(call_data);
    // println!("{:?}", encoded_call_data);
    // let h = client
    //     .tx()
    //     .sign_and_submit_then_watch(&data_transfer, &signer, extrinsic_params)
    //     .await
    //     ?
    //     .wait_for_finalized_success()
    //     .await
    //     ?;
    let additional_and_extra_params = {
        let runtime = client.runtime_version();
        <<AvailConfig as Config>::ExtrinsicParams as ExtrinsicParams<<AvailConfig as Config>::Index, <AvailConfig as Config>::Hash>>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            client.genesis_hash(),
            extrinsic_params,
        )
    };

    let signature:<AvailConfig as Config>::Signature = {
        let mut bytes = Vec::new();
        encoded_call_data.encode_to(&mut bytes);
        additional_and_extra_params.encode_extra_to(&mut bytes);
        additional_and_extra_params.encode_additional_to(&mut bytes);
        println!("{:?}", bytes);
        if bytes.len() > 256 {
            signer.sign(<AvailConfig as Config>::Hasher::hash_of(&Encoded(bytes)).as_ref())
        } else {
            signer.sign(&bytes)
        }
    };
    let signature_2:<AvailConfig as Config>::Signature = avail_subxt::utils::MultiSignature::Sr25519([
        120, 186, 202, 206, 132, 210,  34, 112, 144,  43, 225,
         72,  72,   7, 226, 168, 104, 168,  30, 196, 167, 208,
        140,  86, 229, 192, 207,  61,  74,  47, 145,  93,  77,
         64,  61,   8, 254,  46, 103,  78, 238,   7, 200, 200,
         81,  84, 150, 110, 150, 235, 220, 128,   0, 251,  84,
        254, 192,  66, 101,  38, 115, 209, 131, 129
      ]);

    let extrinsic = {
        let mut encoded_inner = Vec::new();
        // "is signed" + transaction protocol version (4)
        (0b10000000 + 4u8).encode_to(&mut encoded_inner);
        // from address for signature
        signer.address().encode_to(&mut encoded_inner);
        // the signature bytes
        signature_2.encode_to(&mut encoded_inner);
        // attach custom extra params
        additional_and_extra_params.encode_extra_to(&mut encoded_inner);
        // and now, call data
        encoded_call_data.encode_to(&mut encoded_inner);
        // now, prefix byte length:
        let len = Compact(
            u32::try_from(encoded_inner.len())
                .expect("extrinsic size expected to be <4GB"),
        );
        let mut encoded = Vec::new();
        len.encode_to(&mut encoded);
        encoded.extend(encoded_inner);
        encoded
    };

    let submittable = SubmittableExtrinsic::from_bytes(
        client.clone(),
        extrinsic,
    );
    let h = submittable.submit_and_watch().await?;
    // let h = client.tx().create_signed(&data_transfer, &signer, extrinsic_params).await?;
    // let hex_h = h.into_encoded();
    // println!("{:?}", hex::encode(hex_h));

    Ok(())

}
