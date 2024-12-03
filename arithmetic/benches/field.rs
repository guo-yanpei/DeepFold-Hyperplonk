use std::time::Instant;

use arithmetic::field::{
    bn_254::Bn254F,
    goldilocks64::{Goldilocks64, Goldilocks64Ext},
    Field,
};
use ark_bn254::Fr;
use ark_ff::UniformRand;
use rand::thread_rng;

fn main() {
    let mut rng = thread_rng();
    let mut x = <Fr as UniformRand>::rand(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x + x * x;
    }
    println!("Fr add_mult {}, {}", start.elapsed().as_millis(), x);

    let mut x = <Fr as UniformRand>::rand(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x + x;
    }
    println!("Fr add {}, {}", start.elapsed().as_millis(), x);

    let mut x = <Fr as UniformRand>::rand(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x * x;
    }
    println!("Fr mult {}, {}", start.elapsed().as_millis(), x);

    let mut x = Goldilocks64Ext::random(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x + x * x;
    }
    println!("Goldilocks64ext add_mult {}, {:?}", start.elapsed().as_millis(), x);

    let mut x = Goldilocks64Ext::random(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x + x;
    }
    println!("Goldilocks64ext add {}, {:?}", start.elapsed().as_millis(), x);

    let mut x = Goldilocks64Ext::random(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x * x;
    }
    println!("Goldilocks64ext mult {}, {:?}", start.elapsed().as_millis(), x);

    let mut x = Goldilocks64::random(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x + x * x;
    }
    println!("Goldilocks64 add_mult {}, {:?}", start.elapsed().as_millis(), x);

    let mut x = Goldilocks64::random(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x + x;
    }
    println!("Goldilocks64 add {}, {:?}", start.elapsed().as_millis(), x);

    let mut x = Goldilocks64::random(&mut rng);
    let start = Instant::now();
    for _ in 0..(1 << 26) {
        x = x * x;
    }
    println!("Goldilocks64 mult {}, {:?}", start.elapsed().as_millis(), x);
}
