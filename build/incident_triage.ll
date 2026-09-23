; ModuleID = "incident_triage"
source_filename = "incident_triage.tfg"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str.0 = private unnamed_addr constant [16 x i8] c"incident_triage\00", align 1
@.str.1 = private unnamed_addr constant [59 x i8] c"[\22pid\22,\22name\22,\22parent\22,\22command_line\22,\22user\22,\22start_time\22]\00", align 1
@.str.2 = private unnamed_addr constant [5 x i8] c"json\00", align 1
@.str.3 = private unnamed_addr constant [30 x i8] c"incident_triage_evidence.json\00", align 1

; --- TraceForge Forensic Runtime C-ABI Declarations ---
declare ptr @traceforge_rt_evidence_init(ptr)
declare i32 @traceforge_rt_collect_system(ptr)
declare i32 @traceforge_rt_collect_processes(ptr, ptr, ptr)
declare i32 @traceforge_rt_collect_network(ptr)
declare i32 @traceforge_rt_collect_files(ptr, ptr, i32, ptr)
declare i32 @traceforge_rt_collect_logs(ptr, ptr)
declare i32 @traceforge_rt_collect_drivers(ptr)
declare i32 @traceforge_rt_evidence_filter(ptr, ptr)
declare i32 @traceforge_rt_evidence_where(ptr, ptr)
declare i32 @traceforge_rt_evidence_limit(ptr, i64)
declare i32 @traceforge_rt_evidence_compute_hash(ptr, ptr)
declare i32 @traceforge_rt_evidence_generate_timeline(ptr)
declare i32 @traceforge_rt_evidence_export(ptr, ptr, ptr)
declare void @traceforge_rt_evidence_free(ptr)

define i32 @main() {
entry:
  %l0 = call ptr @traceforge_rt_evidence_init(ptr @.str.0)
  %l2 = call i32 @traceforge_rt_collect_system(ptr %l0)
  %l3 = call i32 @traceforge_rt_collect_processes(ptr %l0, ptr @.str.1, ptr null)
  %l4 = call i32 @traceforge_rt_collect_network(ptr %l0)
  %l5 = call i32 @traceforge_rt_collect_drivers(ptr %l0)
  %v0 = call i32 @traceforge_rt_evidence_export(ptr %l0, ptr @.str.2, ptr @.str.3)
  %l1 = add i32 0, 0
  call void @traceforge_rt_evidence_free(ptr %l0)
  ret i32 %l1
}

