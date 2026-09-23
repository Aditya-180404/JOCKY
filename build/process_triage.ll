; ModuleID = "process_triage"
source_filename = "process_triage.tfg"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str.0 = private unnamed_addr constant [15 x i8] c"process_triage\00", align 1
@.str.1 = private unnamed_addr constant [52 x i8] c"[\22pid\22,\22name\22,\22parent\22,\22command_line\22,\22start_time\22]\00", align 1
@.str.2 = private unnamed_addr constant [5 x i8] c"json\00", align 1
@.str.3 = private unnamed_addr constant [29 x i8] c"process_triage_evidence.json\00", align 1

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
declare i32 @traceforge_rt_evidence_export(ptr, ptr, ptr)
declare void @traceforge_rt_evidence_free(ptr)

define i32 @main() {
entry:
  %v0 = call ptr @traceforge_rt_evidence_init(ptr @.str.0)
  %v1 = call i32 @traceforge_rt_collect_system(ptr %v0)
  %v2 = call i32 @traceforge_rt_collect_processes(ptr %v0, ptr @.str.1, ptr null)
  %v3 = call i32 @traceforge_rt_collect_network(ptr %v0)
  %v4 = call i32 @traceforge_rt_evidence_export(ptr %v0, ptr @.str.2, ptr @.str.3)
  call void @traceforge_rt_evidence_free(ptr %v0)
  ret i32 0
}

