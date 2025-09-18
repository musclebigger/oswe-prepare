# 利用curl去查看请求时长
curl -X POST -H "Content-Type: application/json" -d '{"url":"http://10.66.66.66"}' http://apigateway:8000/files/import -s -w 'Total: %{time_total} microseconds\n' -o /dev/null