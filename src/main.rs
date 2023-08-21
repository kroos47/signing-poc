#![allow(dead_code)]
#![allow(unused_variables)]

use std::borrow::Cow;

use avail_subxt::{config::Hasher, primitives::extrinsic_params, Address};
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
    tx::{PairSigner, Payload, Signer, SubmittableExtrinsic},
    utils::{MultiAddress,Encoded}, config::{ExtrinsicParams, substrate::Era, Config},
};

use schnorrkel::{
	derive::{ChainCode, Derivation, CHAIN_CODE_LENGTH},
	signing_context, ExpansionMode, Keypair, MiniSecretKey, PublicKey, SecretKey,
};
const SIGNING_CTX: &[u8] = b"substrate";

async fn poc1() -> Result<()>{
    let args = Opts::from_args();
    let client = build_client(args.ws, args.validate_codegen)
        .await?;
    let signer: PairSigner<AvailConfig, Pair> =
        PairSigner::new(AccountKeyring::Alice.pair());
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
        <<AvailConfig as Config>::ExtrinsicParams as ExtrinsicParams<<AvailConfig as avail_subxt::config::Config>::Index, <AvailConfig as avail_subxt::config::Config>::Hash>>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            client.genesis_hash(),
            extrinsic_params,
        )
    };
    println!("{:?}", additional_and_extra_params);

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
        signature.encode_to(&mut encoded_inner);
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
    let h = submittable.submit_and_watch().await?.wait_for_in_block().await?;
    // let h = client.tx().create_signed(&data_transfer, &signer, extrinsic_params).await?;
    // let hex_h = h.into_encoded();
    // println!("{:?}", hex::encode(hex_h));

    Ok(())

}


async fn poc2() -> Result<()>{
    let args = Opts::from_args();
    let client = build_client(args.ws, args.validate_codegen)
        .await?;
    let signer= AccountKeyring::Alice.pair();
    let bytes_keypair: [u8; 96] = [254, 86, 107, 39, 253, 64, 136, 28, 153, 194, 176, 53, 124, 196, 94, 89, 121, 169, 168, 77, 115, 191, 211, 60, 252, 204, 6, 160, 89, 44, 140, 3, 190, 89, 217, 184, 30, 126, 7, 170, 233, 104, 93, 94, 107, 220, 232, 230, 170, 197, 111, 15, 249, 117, 229, 178, 58, 154, 167, 198, 90, 114, 109, 96, 204, 51, 5, 105, 96, 252, 96, 37, 61, 40, 146, 1, 214, 56, 62, 141, 50, 56, 200, 166, 114, 236, 72, 252, 159, 184, 99, 246, 193, 115, 182, 127];
    println!("{:?}", bytes_keypair);
    let schnorrkel_keypair = Keypair::from_bytes(&bytes_keypair).unwrap();
 
    let schnorrkel_public_key = schnorrkel_keypair.public.to_bytes();
    let schnorrkel_private_key = schnorrkel_keypair.secret.to_bytes();
    println!("{:?} \n\n{:?}", schnorrkel_private_key, schnorrkel_public_key);
    let converted = conv_array(&schnorrkel_private_key);
    println!("\nprivate key{:?}", converted);
    let substrate_keypair = Pair::from_seed_slice(&schnorrkel_private_key).unwrap();
    let substrate_public_key = substrate_keypair.public();
    
    // let alice_signer: PairSigner<AvailConfig, Pair> = PairSigner::new(signer.clone());
    let alice_account_id = AccountId::from(substrate_keypair.public());
    println!("{:?}", substrate_keypair.public().to_ss58check());
    let example_data = b"example".to_vec();
        let data_transfer = api::tx()
        .data_availability()
        .submit_data(BoundedVec(example_data.clone()));
    let extrinsic_params = AvailExtrinsicParams::new_with_app_id(1.into());
    let extrinsic_params_clone = extrinsic_params.clone();
    let h = client.tx().create_partial_signed(&data_transfer, &alice_account_id,extrinsic_params_clone).await?;
    let nonce = client.rpc().system_account_next_index(&alice_account_id).await?;
    // let signed = h.sign(&alice_signer);
    // signed.submit_and_watch().await?.wait_for_in_block().await?;
    let additional_and_extra_params = {
        let runtime = client.runtime_version();
        <<AvailConfig as Config>::ExtrinsicParams as ExtrinsicParams<<AvailConfig as avail_subxt::config::Config>::Index, <AvailConfig as avail_subxt::config::Config>::Hash>>::new(
            runtime.spec_version,
            runtime.transaction_version,
            nonce,
            client.genesis_hash(),
            extrinsic_params,
        )
    };
    println!("{:?}", additional_and_extra_params);
    let mut bytes = h.call_data().to_vec();
    let sig = {
        additional_and_extra_params.encode_extra_to(&mut bytes);
        additional_and_extra_params
        .encode_additional_to(&mut bytes);
    if bytes.len() > 256 {
        let x = <AvailConfig as Config>::Hasher::hash_of(&Encoded(bytes));
        x.as_ref().to_vec()
    } else {
        bytes
    }
    };
    println!("\n signature to be sogned{:?}", sig);
    let sign3:[u8;64] = [
        25, 108, 226,  34, 124,  40, 113, 160,  37,  78,  99,
       126, 237,  46,  41, 182,  39, 237, 229, 213, 196, 123,
       131, 108,   9, 241, 156, 132, 224,  66,  17,   5, 251,
       144, 226,  62, 174, 181, 131,  56, 121,  88, 193,  20,
       111, 243,  93, 101,  12,  11, 107,  29, 184, 252, 137,
        68, 187, 158,   8,  34, 223, 103,  38, 126
     ];
    let context = signing_context(SIGNING_CTX);
    let sign:<AvailConfig as Config>::Signature= signer.sign(&sig).into();
    let sign2= schnorrkel_keypair.sign(context.bytes(&sig));
    let new_sign:<AvailConfig as Config>::Signature = conv_to_avail(sign3);
    let conv:<AvailConfig as Config>::Signature = conv(sign2);
    println!("\n sign2{:?}", sign2);
    let signer_add:Address = alice_account_id.into();
    let post_sign = h.sign_with_address_and_signature(&signer_add, &new_sign);
    post_sign.submit_and_watch().await?.wait_for_in_block().await?;
    
    
    Ok(())
}

fn conv(s: schnorrkel::Signature) -> <AvailConfig as Config>::Signature {
    avail_subxt::utils::MultiSignature::Sr25519(s.to_bytes())
}
fn conv_to_avail(s: [u8;64]) -> <AvailConfig as Config>::Signature {
    avail_subxt::utils::MultiSignature::Sr25519(s)
}

fn conv_array(arr: &[u8;64]) -> &[u8]{
    let ar = &arr[0..32];
    ar
}

#[async_std::main]
async fn main() -> Result<()> {
    poc2().await?;
    #[cfg(feature = "poc1")]
    poc1().await?;
    Ok(())
}
