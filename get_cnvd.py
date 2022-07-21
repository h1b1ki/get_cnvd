import asyncio
import sys
import urllib.parse
from time import sleep
from pyppeteer import *

# Class for colors
class color:
    red = '\033[91m'
    gold = '\033[93m'
    blue = '\033[36m'
    green = '\033[92m'
    no = '\033[0m'

def help():
    print(rf"""Cnvd interrogator outputs the corresponding cnvd according to the given CVE

Usage:
  python3 get_cnvd.py -c <cve-id>
  python3 get_cnvd.py -h

Options:
  -c    Target CVE number, the format must be {color.gold}cve-x-x{color.no}.
  -h    Show this help menu.
""")
    exit()

# 请求拦截器函数，设置拦截条件并可作修改
'''async def intercept_request(interceptedRequest):
    interceptedRequest.headers["content-type"] = "application/x-www-form-urlencoded"
    param = 'keyword=&condition=1&keywordFlag=0&cnvdId=&cnvdIdFlag=0&baseinfoBeanbeginTime=&baseinfoBeanendTime=&baseinfoBeanFlag=0&refenceInfo=CVE-2020-1472&referenceScope=1&manufacturerId=-1&categoryId=-1&editionId=-1&causeIdStr=&threadIdStr=&serverityIdStr=&positionIdStr='
    data = {
        'method': 'POST',
        'postData': param,  # 注意格式，格式错误无法重置请求
        #'url': interceptedRequest.url,
        'headers': interceptedRequest.headers
    }
    await interceptedRequest.continue_(data)
'''
async def CVE_query(page,cve,browser):
    # 进入登录页面，运行js，填写用户名，密码
    await page.goto('https://www.cnvd.org.cn/flaw/list?flag=true')
    await page.waitForNavigation()
    await page.waitFor("input#highLevelSearch")
    await page.click("input#highLevelSearch")
    await page.waitFor("select#referenceScope")
    #选择下拉框内容中的cve
    await page.select("select#referenceScope",'1')
    #模拟用户输入提交cve编号
    await page.waitFor("#refenceInfo")
    #CVE-2020-1472
    await page.type('#refenceInfo', cve)
    sleep(0.5)
    #点击搜索
    await page.waitFor("span.ui-button-text")
    #querySelectorAll()，缩写 JJ() ,返回多个,没有返回空列表[]
    #button = await page.JJ("span.ui-button-text")

    #div.ui-dialog-buttonpane :nth-of-type(2)
    #伪类 :nth-of-type() 来选择是第几个父元素
    await page.click('div.ui-dialog-buttonpane :nth-of-type(2)')
    #document.querySelectorAll("td>a")
    #要有延迟不让还没跳转就输出了
    sleep(2)
    #要切换页面
    # bringToFront()只是让指定标签页在最前,page操作的页面依旧是原来的界面
    # 用pageX=pageList[-1]将page操作的网页设置为弹出的,才能拿到正确数据
    pageList = await browser.pages()  # pages() 获取pageList
    pageList = await browser.pages()
    #print(pageList)
    await pageList[-1].bringToFront()  # bringToFront() 切换到该页面
    page2 = pageList[-1]
    sleep(0.5)
    await page2.waitFor('div.blkContainerPblk')
    #协程函数 querySelectorAllEval(selector:str，pageFunction:str，*args)可简写为JJeval()
    #selector(str)-选择器
    #pageFunction(str)-要在浏览器上运行的JavaScript函数的字符串，此函数将匹配元素的数组作为第一个参数
    #args(Any)-传递给pageFunction的其他参数。
    test = await page2.JJeval("div>div>table>tbody>tr>td>a", 'nodes => nodes.map(node => node.href)')
    if test:
        print(test)
    else:
        print(f'Corresponding cnvd {color.red} not found{color.no}. Maybe the CVE ID has {color.green}no corresponding {color.no} CNVD ID')
    
    


async def main(cve):
    browser = await launch(headless=True, args=['--disable-infobars'], dumpio=True)
    page = await browser.newPage()
    #await page.setRequestInterception(True)
    #page.on('request', lambda req: asyncio.ensure_future(intercept_request(req)))
    await page.evaluateOnNewDocument('''() => {
        Object.defineProperty(navigator, 'webdriver', {
        get: () => undefined
        })
        }
    ''')
    #response = await page.goto('https://www.cnvd.org.cn/flaw/list?flag=true')
    await CVE_query(page,cve,browser)
    #responseBody = await response.text()
    input('Press enter to close after inquiry')
    await page.close()
    await browser.close()


if __name__ == '__main__':
    args = ['-h','-c']
    # Print help if specified or if a target or authentication is not provided
    if args[0] in sys.argv or args[1] not in sys.argv:
        help()

    #query
    if args[1] in sys.argv:
        CVE_id=sys.argv[sys.argv.index(args[1]) + 1]
        try:
            if 'CVE' not in CVE_id.upper():
                raise
            asyncio.run(main(CVE_id))
        except:
            print(f"{color.blue}ERRORED: The format of the query should be {color.red}cve-x-x{color.no}")
            help()


