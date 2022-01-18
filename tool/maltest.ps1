$todate = Get-Date -Format "MMddyyHHmm"
Out-File -FilePath ${Env:UserProfile}\test_$todate.txt