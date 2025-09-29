use lib_identity::wallets::dao_hierarchy_demo;

fn main() -> anyhow::Result<()> {
    // Simple println initialization instead of tracing
    println!("🏛️ Hierarchical DAO Wallet System Demonstration");
    println!("================================================");

    
    match dao_hierarchy_demo::demonstrate_dao_hierarchy() {
        Ok(()) => {
            println!("\n✅ Hierarchical DAO system demonstration completed successfully!");
        }
        Err(e) => {
            eprintln!("\n❌ Demonstration failed: {}", e);
            return Err(e);
        }
    }
    
    Ok(())
}