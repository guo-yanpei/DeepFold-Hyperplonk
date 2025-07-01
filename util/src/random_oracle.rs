use seal_fhe::{
    Asym, BFVEncoder, Ciphertext, Context, EncryptionParameters, Encryptor, KeyGenerator, PlainModulus, Plaintext,
};

type T = Plaintext;

#[derive(Debug, Clone)]
pub struct RandomOracle<'a> {
    pub folding_challenges: Vec<T>,
    ctx: &'a Context,
    params: &'a EncryptionParameters,
}

impl<'a> RandomOracle<'a> {
    pub fn new(
        total_round: usize,
        query_num: usize,
        ctx: &'a Context,
        params: &'a EncryptionParameters,
        key_gen: &'a KeyGenerator,
    ) -> Self {
        let encoder = BFVEncoder::new(ctx, params).unwrap();

        // let public_key = key_gen.create_public_key();
        // let encryptor = Encryptor::<Asym>::new(ctx, &public_key).unwrap();
        RandomOracle {
            folding_challenges: (0..total_round)
                .into_iter()
                .map(|_| T::random_pt(&encoder))
                .collect(),
            ctx,
            params,
        }
    }
}
