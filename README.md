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

-----
- macop build 读取当前工作目录下的 macop.yaml 文件 -f 制定特定文件构建, 构建的目录是 macop.yaml 文件 所在的目录作为相对目录
- macop push 同理
- macop pull 拉取软件包
- macop run ccheers/cctest:v1.7 运行软件
  -  “--” 之后的参数作为覆盖参数传递给 entrypoint
- macop delete ccheers/cctest:v1.7 删除软件清理空间