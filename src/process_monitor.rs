use regex::Regex;
use serde::Deserialize;
use tokio::sync::mpsc::UnboundedReceiver;
use windows::Win32::System::Threading::{OpenProcess, SetPriorityClass, PROCESS_CREATION_FLAGS, REALTIME_PRIORITY_CLASS, HIGH_PRIORITY_CLASS, ABOVE_NORMAL_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, BELOW_NORMAL_PRIORITY_CLASS, IDLE_PRIORITY_CLASS, SetProcessAffinityMask, PROCESS_SET_INFORMATION};
use wmi::*;
use tokio_stream::StreamExt;

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_ProcessStartTrace")]
#[serde(rename_all = "PascalCase")]
struct ProcessStartTrace {
    process_id: u32,
    process_name: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename = "Win32_Process")]
#[serde(rename_all = "PascalCase")]
struct WinProcess {
    process_id: u32,
    name: String,
}

struct ProcessInfo {
    process_id: u32,
    process_name: String,
}

impl From<ProcessStartTrace> for ProcessInfo {
    fn from(value: ProcessStartTrace) -> Self {
        Self {
            process_id: value.process_id,
            process_name: value.process_name
        }
    }
}

impl From<WinProcess> for ProcessInfo {
    fn from(value: WinProcess) -> Self {
        Self {
            process_id: value.process_id,
            process_name: value.name
        }
    }
}

#[derive(Deserialize, Debug)]
struct ProcessRule {
    #[serde(with = "serde_regex")]
    pattern: Regex,
    priority: Option<ProcessPriority>,
    core_affinity: Option<Vec<usize>>
}

#[derive(Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum ProcessPriority {
    Realtime,
    High,
    AboveNormal,
    Normal,
    BelowNormal,
    Low
}

impl From<ProcessPriority> for PROCESS_CREATION_FLAGS {
    fn from(value: ProcessPriority) -> Self {
        match value {
            ProcessPriority::Realtime => REALTIME_PRIORITY_CLASS,
            ProcessPriority::High => HIGH_PRIORITY_CLASS,
            ProcessPriority::AboveNormal => ABOVE_NORMAL_PRIORITY_CLASS,
            ProcessPriority::Normal => NORMAL_PRIORITY_CLASS,
            ProcessPriority::BelowNormal => BELOW_NORMAL_PRIORITY_CLASS,
            ProcessPriority::Low => IDLE_PRIORITY_CLASS,
        }
    }
}

impl ProcessRule {
    fn apply(&self, process: &ProcessInfo) -> anyhow::Result<()>{
        if self.pattern.is_match(&process.process_name) {
            let process_handle = unsafe { OpenProcess(PROCESS_SET_INFORMATION, false, process.process_id) }?;
            
            if let Some(ref core_affinity) = self.core_affinity {
                let affinity_mask = core_affinity.iter().fold(0, |mask, core| mask | (1usize << core));
                let result = unsafe { SetProcessAffinityMask(process_handle, affinity_mask) };
                if !result.as_bool() {
                    anyhow::bail!("Failed to set core affinity for process {:?}", process.process_name);
                }
            }

            if let Some(priority) = &self.priority {
                let result = unsafe { SetPriorityClass(process_handle, (*priority).into()) };
                if !result.as_bool() {
                    anyhow::bail!("Failed to set priority for process {:?}", process.process_name);
                }
            }

            println!("Applied rule {:?} (priority={:?} affinity={:?}) to process {:?} {:?}",
                self.pattern.as_str(), self.priority, self.core_affinity,
                process.process_id, process.process_name)
        }
        Ok(())
    }
}

#[derive(Deserialize, Debug)]
struct ProcessRuleSet {
    rules: Vec<ProcessRule>
}

impl ProcessRuleSet {
    fn apply(&self, process: &ProcessInfo) {
        self.rules.iter().for_each(|rule| { 
            if let Err(error) = rule.apply(process) {
                println!("Error applying rule: {:?} for process {:?}", error, process.process_name);
            }
        });
    }
}

async fn monitor_new_processes(rule_set: &ProcessRuleSet, once: bool) -> anyhow::Result<()> {
    let wmi_con = WMIConnection::new(COMLibrary::new()?)?;

    // Start receiving new processes before checking running processes or
    // there will be a period where some new processes get ignored
    let mut process_start_stream = wmi_con.async_notification::<ProcessStartTrace>()?;

    // Apply rules to all running processes
    let running_process: Vec<WinProcess> = wmi_con.async_query().await?;
    println!("Processes: {:?}", running_process.len());
    running_process.into_iter().for_each(|process| {
        let process_info: ProcessInfo = process.into();
        rule_set.apply(&process_info)
    });

    if !once {
        while let Some(Ok(event)) = process_start_stream.next().await {
            let process_info: ProcessInfo = event.into();
            rule_set.apply(&process_info);
        }
    }

    Ok(())
}

pub(crate) async fn rule_applier(rule_file_path: &str, shutdown_recv: &mut UnboundedReceiver<()>, once: bool) -> anyhow::Result<()> {
    let rule_set: ProcessRuleSet = std::fs::File::open(rule_file_path)
                                        .map(|file| serde_json::from_reader(file)
                                            .map_err(|err| { println!("{}: {}", rule_file_path, err) })
                                            .unwrap_or(ProcessRuleSet { rules: vec!() }))
                                        .map_err(|err| { println!("{}: {}", rule_file_path, err) })
                                        .unwrap_or(ProcessRuleSet { rules: vec!() });

    println!("Rules: {:?}", rule_set.rules.len());

    tokio::select! {
        // Apply rules to new processes
        output = monitor_new_processes(&rule_set, once) => output,
        // Or wait for shutdown signal
        _ = shutdown_recv.recv() => {
            println!("Shutting down process monitor");
            Ok(())
        }
    }
}