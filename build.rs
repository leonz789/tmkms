// build.rs
// Build script for generating Rust code from Protocol Buffer definitions

fn main() {
    // Proto files to compile
    let protos: &[&str] = &["proto/privval/v1/types.proto"];
    
    // Include directories for proto compilation
    let includes: &[&str] = &["proto"];
    
    // Generate Rust code from proto files
    prost_build::Config::new()
        .bytes(&[".privval.v1.PriceFeedRequest.raw_data"])
        .compile_protos(protos, includes)
        .unwrap();
}
