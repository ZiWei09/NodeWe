use nodewe_runtime::NodeId;

#[test]
fn node_ids_are_distinct_routing_targets() {
    let a = NodeId::new("node-a").unwrap();
    let b = NodeId::new("node-b").unwrap();
    assert_ne!(a, b);
    assert_eq!(a.as_str(), "node-a");
}
