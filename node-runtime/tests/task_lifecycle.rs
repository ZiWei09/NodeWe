use nodewe_runtime::TaskState;

#[test]
fn successful_task_has_explicit_terminal_transition() {
    assert!(TaskState::Running.can_transition_to(&TaskState::Succeeded));
    assert!(!TaskState::Succeeded.can_transition_to(&TaskState::Running));
}

#[test]
fn cancellation_requires_running_or_approved_task() {
    assert!(TaskState::Approved.can_transition_to(&TaskState::CancelRequested));
    assert!(!TaskState::Succeeded.can_transition_to(&TaskState::CancelRequested));
}
