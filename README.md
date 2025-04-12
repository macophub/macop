# macop

```bash
 go run main.go serve
```

## CDN
白嫖 docker hub or npm hub ？
倾向于 docker hub

可以使用 docker，npm，python

macop pull
macop push
macop list （查看有哪些 mcp）
macop create

## 思考1 （一期）
macop run server1
macop run server2


## 思考2 （二期）
client -> prompt -> {
 天气： name macop 传参1
 SQL:  name macop 传参2
}


原始 ./mcp-svc1 ./mcp-svc2

未来 ？
macop dispatcher -> 命令行 stdio -> mcp server
os.exec("")

ollma -> cgo 调用不同大模型 -> 处理数据