# get_cnvd
## 前言
- 功能：输入cve,输出cnvd编号
- 目标网址:https://www.cnvd.org.cn/flaw/list?flag=true
- 该网址有js混淆cookie加反爬机制
## 思路
1. 直接驱动浏览器抓取数据，无视js加密
2. 找到本地加密的js代码，使用python的相关库直接运行js代码
3. 找到本地加密的js代码，理清加密逻辑，然后用python代码来模仿js代码的流程
- 第一个最直接方便,便决定用python的pyppeteer来操作浏览器抓取对应的编号
