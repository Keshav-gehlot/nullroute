# WorkManager instantiates workers reflectively.
-keep class * extends androidx.work.ListenableWorker { <init>(...); }
