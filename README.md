# log4j-Scan-Burpsuite
Log4j漏洞（CVE-2021-44228）的Burpsuite检测插件

功能：开关(ON/OFF)、过滤(Filter)、发送(Send)


# DNSLog
https://log.xn--9tr.com/

# 插件页面展示
![image](https://user-images.githubusercontent.com/54879520/146352797-9211458b-989e-4386-80a3-40f38a1e3d47.png)
![image](https://user-images.githubusercontent.com/54879520/146352764-86d3c09f-f6d6-4107-867a-4e7860547959.png)


# 使用
被动检测所有通过Burpsuite的流量包、手动发送需要检测的请求包进行检测

Passively detect all traffic packets passing through Burpsuite, and manually send request packets that need to be detected for detection

# 功能

通过开关按钮选择开启或关闭扫描功能，开启后所有通过Burpsuite的流量都将进行log4j漏洞检测（此处偶尔出现BUG，实际开关状态以文字显示为主）

Use the switch button to choose to turn on or off the scanning function. After turning on, all traffic passing through Burpsuite will be tested for log4j vulnerabilities (BUG occasionally appears here, and the actual switch status is mainly displayed in text)
![image](https://user-images.githubusercontent.com/54879520/146351788-4233ddba-e2a1-46ef-9323-01ad14a6dc12.png)


通过输入域名进行过滤，只针对需要检测的域名相关报文进行检测

Filter by entering the domain name, and detect only the domain-related packets that need to be detected
![image](https://user-images.githubusercontent.com/54879520/146352060-29bfbeb1-7166-4065-a6ed-39111f4ad0cd.png)


通过点击“扫描列表清空”按钮，清理扫描列表

Clear the scan list by clicking the "Clear Scan List" button
![image](https://user-images.githubusercontent.com/54879520/146353005-ae21447f-a81e-419d-b75e-8b5340477b05.png)
![image](https://user-images.githubusercontent.com/54879520/146353057-7d73cc31-c4a0-4a17-beaf-5016b8c40a5e.png)

选择需要发送的请求并且右键点击，发送至log4j Scan插件进行检测

Select the request to be sent and right-click to send it to the log4j Scan plugin for detection
![image](https://user-images.githubusercontent.com/54879520/146351539-4dc42228-424a-47aa-a35d-8ba4275f61a0.png)


本工具仅供学习研究自查使用，切勿用于非法用途，由使用该工具产生的一切风险均与本人无关！

This tool is only for study, research and self-examination, and should not be used for illegal purposes. 
