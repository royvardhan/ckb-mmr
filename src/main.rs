use ckb_mmr_wasm::generate_root;

fn main() {
    let result = generate_root(100, 63);
    match result {
        Ok(mmr_result) => println!("{}", mmr_result),
        Err(e) => eprintln!("Error: {:?}", e),
    }
}
