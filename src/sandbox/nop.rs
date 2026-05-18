use super::{SandboxEnforcer, SandboxPolicy, WrappedCommand};

#[allow(dead_code)]
pub struct NopEnforcer;

impl SandboxEnforcer for NopEnforcer {
    fn wrap_command(
        &self,
        _policy: &SandboxPolicy,
        cmd: &WrappedCommand,
    ) -> anyhow::Result<WrappedCommand> {
        Ok(WrappedCommand {
            program: cmd.program.clone(),
            args: cmd.args.clone(),
            env: cmd.env.clone(),
        })
    }
}
