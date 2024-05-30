use crate::encoding::mvx::{ed25519_key, Message, WeightedSigners};
use crate::error::ContractError;
use crate::payload::Payload;
use cosmwasm_std::HexBinary;
use multisig::msg::SignerWithSig;
use multisig::verifier_set::VerifierSet;
use multiversx_sc_codec::top_encode_to_vec_u8;

pub struct Proof {
    pub signers: WeightedSigners,
    pub signatures: Vec<Option<[u8; 64]>>,
}

impl Proof {
    pub fn new(verifier_set: &VerifierSet, signers_with_sigs: Vec<SignerWithSig>) -> Self {
        let signers = WeightedSigners::from(verifier_set);

        let mut signers_with_sigs = signers_with_sigs
            .into_iter()
            .map(|signer| {
                let key = ed25519_key(&signer.signer.pub_key).expect("not ed25519 key");

                (key, signer.signature)
            })
            .collect::<Vec<_>>();

        signers_with_sigs.sort_by_key(|signer| signer.0);

        let mut signatures = Vec::new();

        let mut signatures_index = 0;
        for signer in signers.signers.iter() {
            let signer_with_sig = signers_with_sigs.get(signatures_index);

            if signer_with_sig.is_some() {
                let signer_with_sig = signer_with_sig.unwrap();

                // Add correct signature if signer order is the same
                if signer.signer == signer_with_sig.0 {
                    signatures_index += 1;

                    let signature = <[u8; 64]>::try_from(signer_with_sig.1.as_ref())
                        .expect("couldn't convert signature to ed25519");

                    signatures.push(Some(signature));

                    continue;
                }
            }

            // Add no signature for signer
            signatures.push(None);
        }

        Proof {
            signers,
            signatures,
        }
    }

    pub fn encode(self) -> Result<Vec<u8>, ContractError> {
        Ok(top_encode_to_vec_u8(&(self.signers, self.signatures))
            .expect("couldn't serialize proof as mvx"))
    }
}

pub fn encode(
    verifier_set: &VerifierSet,
    signers: Vec<SignerWithSig>,
    payload: &Payload,
) -> Result<HexBinary, ContractError> {
    let proof = Proof::new(verifier_set, signers);

    let data = match payload {
        Payload::Messages(messages) => {
            let messages: Vec<_> = messages
                .iter()
                .map(Message::try_from)
                .collect::<Result<_, _>>()?;

            let messages =
                top_encode_to_vec_u8(&messages).expect("couldn't serialize messages as mvx");
            let proof = proof.encode()?;

            let messages: HexBinary = messages.into();
            let proof: HexBinary = proof.into();

            // Since for MultiversX the full payload is not all hex, we actually double encode some
            // values as hex here, but the relayer will first decode this payload as utf8 string
            // and then do the appropriate transaction
            let result = format!("approveMessages@{}@{}", messages, proof);

            HexBinary::from(result.as_bytes())
        }
        Payload::VerifierSet(new_verifier_set) => {
            let new_verifier_set = WeightedSigners::from(new_verifier_set).encode()?;
            let proof = proof.encode()?;

            let new_verifier_set: HexBinary = new_verifier_set.into();
            let proof: HexBinary = proof.into();

            // Since for MultiversX the full payload is not all hex, we actually double encode some
            // values as hex here, but the relayer will first decode this payload as utf8 string
            // and then do the appropriate transaction
            let result = format!("rotateSigners@{}@{}", new_verifier_set, proof);

            HexBinary::from(result.as_bytes())
        }
    };

    Ok(data)
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::HexBinary;
    use itertools::Itertools;

    use multisig::key::{KeyType, KeyTyped, Signature};
    use multisig::msg::{Signer, SignerWithSig};

    use crate::encoding::mvx::execute_data::Proof;
    use crate::encoding::mvx::{ed25519_key, WeightedSigners};
    use crate::test::test_data::{
        curr_verifier_set, curr_verifier_set_ed25519, messages_mvx,
        verifier_set_from_pub_keys_ed25519,
    };
    use crate::{encoding::mvx::execute_data::encode, payload::Payload};

    #[test]
    fn rotate_signers_function_data() {
        // RotateSigners function call data generated by sc-axelar-cgp-rs tests

        let new_pub_keys = vec![
            "8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8",
            "b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba",
            "0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1",
        ];

        let new_verifier_set = verifier_set_from_pub_keys_ed25519(new_pub_keys);
        let verifier_set = curr_verifier_set_ed25519();

        // Generated signatures are already sorted by weight and address
        let sigs: Vec<_> = vec![
            "5c98a98d1e47adecf83a10d4fdc542aae1cb13ab8e6d3f5e237ad75ccb6608631c0d3f8735e3f5f481e82f088fe5215d431ae8c6abf68b96797df4bbe610cd05",
            "ca0999eac93ee855ea88680b8094660635a06743e9acdb8d1987a9c48a60e9f794bd22a10748bb9c3c961ddc3068a96abfae00a9c38252a4b3ad99caeb060805",
            "deca8b224a38ad99ec4cb4f3d8e86778544c55ab0c4513ce8af834b81b3e934eef29727cc76c364f316a44c2eea82fa655f209f0c5205a209461d8a7fbbacf03",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let payload = Payload::VerifierSet(new_verifier_set);

        let execute_data = encode(&verifier_set, signers_with_sigs, &payload).unwrap();

        // rotateSigners - name of function
        // @ - separator of data in MultiversX format
        //
        // Then we have the new signers passed as first argument to function:
        // 00000003 - length of new signers
        // 0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1 - first new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // 8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8 - second new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba - third new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // 00000001 03 - length of biguint threshold followed by 3 as hex
        // 290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563 - the nonce (keccak256 hash of Uin256 number 0, created_at date)
        // @ - separator of data in MultiversX format
        //
        // Then we have the proof passed as second argument to function:
        // 00000005 - length of signers
        // 0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1 00000001 01 - first signer with weight
        // 8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8 00000001 01 - second signer with weight
        // b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba 00000001 01 - third signer with weight
        // ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6 00000001 01 - fourth signer with weight
        // ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a4449 00000001 01 - fifth signer with weight
        // 00000001 03 - length of biguint threshold followed by 3 as hex
        // 290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563 - the nonce (keccak256 hash of Uin256 number 0, created_at date)
        // 00000005 - length of signatures
        // 01 5c98a98d1e47adecf83a10d4fdc542aae1cb13ab8e6d3f5e237ad75ccb6608631c0d3f8735e3f5f481e82f088fe5215d431ae8c6abf68b96797df4bbe610cd05 - first signature encoded as a Some option
        // 01 ca0999eac93ee855ea88680b8094660635a06743e9acdb8d1987a9c48a60e9f794bd22a10748bb9c3c961ddc3068a96abfae00a9c38252a4b3ad99caeb060805 - second signature encoded as a Some option
        // 01 deca8b224a38ad99ec4cb4f3d8e86778544c55ab0c4513ce8af834b81b3e934eef29727cc76c364f316a44c2eea82fa655f209f0c5205a209461d8a7fbbacf03 - third signature encoded as a Some option
        // 00 - fourth signature encoded as a None option (the fourth signer didn't specify any signature)
        // 00 - fifth signature encoded as a None option (the fifth signer didn't specify any signature)
        assert_eq!(
            std::str::from_utf8(execute_data.as_slice()).unwrap(),
            format!(
                "rotateSigners@{}@{}",
                "000000030139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e100000001018049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f80000000101b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba00000001010000000103290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563",
                "000000050139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e100000001018049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f80000000101b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba0000000101ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b60000000101ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a444900000001010000000103290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56300000005015c98a98d1e47adecf83a10d4fdc542aae1cb13ab8e6d3f5e237ad75ccb6608631c0d3f8735e3f5f481e82f088fe5215d431ae8c6abf68b96797df4bbe610cd0501ca0999eac93ee855ea88680b8094660635a06743e9acdb8d1987a9c48a60e9f794bd22a10748bb9c3c961ddc3068a96abfae00a9c38252a4b3ad99caeb06080501deca8b224a38ad99ec4cb4f3d8e86778544c55ab0c4513ce8af834b81b3e934eef29727cc76c364f316a44c2eea82fa655f209f0c5205a209461d8a7fbbacf030000"
            )
        );
    }

    #[test]
    fn approve_messages_function_data() {
        // ApproveMessages function call data generated by sc-axelar-cgp-rs tests
        let verifier_set = curr_verifier_set_ed25519();

        // Generated signatures are already sorted by weight and evm address
        let sigs: Vec<_> = vec![
            "9543286a58ded1c031fcf8e5fcdc7c5b48b6304c539bdf7a30a0b780451a64318420fe654a13be7a33cae4f221cd26e1e033d01da144901453474c73b520450d",
            "199b7e0f25ff4c24637bbdfdc18d338f422793f492a81140afd080019061088ddf667f018d88928a28dcb77a2c253c66ee5a83be2d4134ff3ab3141f0fdb170d",
            "4f883c316682c6e000bf4c92536a138f78c6af265f4f13d7210110e40350bb4d99e049677db13e7c12f8a4e617a5cb9bf32f5142cd58f7146505078e2d675703",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let payload = Payload::Messages(messages_mvx());

        let execute_data = encode(&verifier_set, signers_with_sigs, &payload).unwrap();

        // approveMessages - name of function
        // @ - separator of data in MultiversX format
        //
        // Then we have the new signers passed as first argument to function:
        // 00000003 - length of new signers
        // 0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1 - first new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // 8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8 - second new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba - third new signer
        // 00000001 01 - length of biguint weight followed by 1 as hex
        // 00000001 03 - length of biguint threshold followed by 3 as hex
        // 290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563 - the nonce (keccak256 hash of Uin256 number 0, created_at date)
        // @ - separator of data in MultiversX format
        //
        // Then we have the proof passed as second argument to function:
        // 00000005 - length of signers
        // 0139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e1 00000001 01 - first signer with weight
        // 8049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f8 00000001 01 - second signer with weight
        // b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba 00000001 01 - third signer with weight
        // ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b6 00000001 01 - fourth signer with weight
        // ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a4449 00000001 01 - fifth signer with weight
        // 00000001 03 - length of biguint threshold followed by 3 as hex
        // 290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563 - the nonce (keccak256 hash of Uin256 number 0, created_at date)
        // 00000005 - length of signatures
        // 01 5c98a98d1e47adecf83a10d4fdc542aae1cb13ab8e6d3f5e237ad75ccb6608631c0d3f8735e3f5f481e82f088fe5215d431ae8c6abf68b96797df4bbe610cd05 - first signature encoded as a Some option
        // 01 ca0999eac93ee855ea88680b8094660635a06743e9acdb8d1987a9c48a60e9f794bd22a10748bb9c3c961ddc3068a96abfae00a9c38252a4b3ad99caeb060805 - second signature encoded as a Some option
        // 01 deca8b224a38ad99ec4cb4f3d8e86778544c55ab0c4513ce8af834b81b3e934eef29727cc76c364f316a44c2eea82fa655f209f0c5205a209461d8a7fbbacf03 - third signature encoded as a Some option
        // 00 - fourth signature encoded as a None option (the fourth signer didn't specify any signature)
        // 00 - fifth signature encoded as a None option (the fifth signer didn't specify any signature)
        assert_eq!(
            std::str::from_utf8(execute_data.as_slice()).unwrap(),
            format!(
                "approveMessages@{}@{}",
                "0000000967616e616368652d31000000443078666638323263383838303738353966663232366235386532346632343937346137306630346239343432353031616533386664363635623363363866333833342d300000002a307835323434346631383335416463303230383663333743623232363536313630356532453136393962000000000000000005006fbc99e58a82ef3c082afcd2679292693049c93710908c3685dc41c2eca11426f8035742fb97ea9f14931152670a5703f18fe8b392f0",
                "000000050139472eff6886771a982f3083da5d421f24c29181e63888228dc81ca60d69e100000001018049d639e5a6980d1cd2392abcce41029cda74a1563523a202f09641cc2618f80000000101b2a11555ce521e4944e09ab17549d85b487dcd26c84b5017a39e31a3670889ba0000000101ca5b4abdf9eec1f8e2d12c187d41ddd054c81979cae9e8ee9f4ecab901cac5b60000000101ef637606f3144ee46343ba4a25c261b5c400ade88528e876f3deababa22a444900000001010000000103290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e56300000005019543286a58ded1c031fcf8e5fcdc7c5b48b6304c539bdf7a30a0b780451a64318420fe654a13be7a33cae4f221cd26e1e033d01da144901453474c73b520450d01199b7e0f25ff4c24637bbdfdc18d338f422793f492a81140afd080019061088ddf667f018d88928a28dcb77a2c253c66ee5a83be2d4134ff3ab3141f0fdb170d014f883c316682c6e000bf4c92536a138f78c6af265f4f13d7210110e40350bb4d99e049677db13e7c12f8a4e617a5cb9bf32f5142cd58f7146505078e2d6757030000"
            )
        );
    }

    #[test]
    fn proof_new_partial_signatures() {
        let verifier_set = curr_verifier_set_ed25519();
        let mut signers = verifier_set.signers.values();

        let first_signature = HexBinary::from_hex("9543286a58ded1c031fcf8e5fcdc7c5b48b6304c539bdf7a30a0b780451a64318420fe654a13be7a33cae4f221cd26e1e033d01da144901453474c73b520450d").unwrap();
        let second_signature = HexBinary::from_hex("199b7e0f25ff4c24637bbdfdc18d338f422793f492a81140afd080019061088ddf667f018d88928a28dcb77a2c253c66ee5a83be2d4134ff3ab3141f0fdb170d").unwrap();

        let first_signer = signers.next().unwrap();
        signers.next(); // Skip a signer
        let second_signer = signers.next().unwrap();

        let mut signers_with_sigs = Vec::new();
        signers_with_sigs.push(
            first_signer.with_sig(
                Signature::try_from((KeyType::Ed25519, first_signature.clone())).unwrap(),
            ),
        );

        signers_with_sigs.push(
            second_signer.with_sig(
                Signature::try_from((KeyType::Ed25519, second_signature.clone())).unwrap(),
            ),
        );

        let proof = Proof::new(&verifier_set, signers_with_sigs);

        assert!(proof.signers == WeightedSigners::from(&verifier_set));
        assert_eq!(proof.signatures.len(), 5);
        assert_eq!(
            proof.signers.signers.get(0).unwrap().signer,
            second_signer.pub_key.as_ref()
        );
        assert_eq!(
            proof.signers.signers.get(3).unwrap().signer,
            first_signer.pub_key.as_ref()
        );

        // Only signatures corresponding to the signers are Some, rest are None
        assert!(proof.signatures.get(0).unwrap().is_some());
        assert_eq!(
            proof.signatures.get(0).unwrap().unwrap(),
            second_signature.as_slice()
        );
        assert!(proof.signatures.get(3).unwrap().is_some());
        assert_eq!(
            proof.signatures.get(3).unwrap().unwrap(),
            first_signature.as_slice()
        );

        assert!(proof.signatures.get(1).unwrap().is_none());
        assert!(proof.signatures.get(2).unwrap().is_none());
        assert!(proof.signatures.get(4).unwrap().is_none());
    }

    #[test]
    #[should_panic(expected = "Public key is not ed25519")]
    fn proof_new_key_error() {
        let verifier_set = curr_verifier_set();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), vec![]);

        let _ = Proof::new(&verifier_set, signers_with_sigs);
    }

    #[test]
    #[should_panic(
        expected = "could not find a match for key type Ed25519 and signature length 65"
    )]
    fn proof_new_signature_error() {
        let verifier_set = curr_verifier_set_ed25519();

        let sigs: Vec<_> = vec![
            "756473c3061df7ea3fef7c52e0e875dca2c93f08ce4f1d33e694d64c713a56842017d92f0a1b796afe1c5343677ff261a072fb210ff3d43cc2784c0774d4da7b1b",
        ].into_iter().map(|sig| HexBinary::from_hex(sig).unwrap()).collect();

        let signers_with_sigs = signers_with_sigs(verifier_set.signers.values(), sigs);

        let _ = Proof::new(&verifier_set, signers_with_sigs);
    }

    fn signers_with_sigs<'a>(
        signers: impl Iterator<Item = &'a Signer>,
        sigs: Vec<HexBinary>,
    ) -> Vec<SignerWithSig> {
        signers
            .sorted_by(|s1, s2| {
                Ord::cmp(
                    &ed25519_key(&s1.pub_key).unwrap(),
                    &ed25519_key(&s2.pub_key).unwrap(),
                )
            })
            .zip(sigs)
            .map(|(signer, sig)| {
                signer.with_sig(Signature::try_from((signer.pub_key.key_type(), sig)).unwrap())
            })
            .collect()
    }
}
