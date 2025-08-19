// Global variables for phishing detection
var testdata;
var prediction;

// Machine Learning prediction function using pre-trained weights
// Returns 1 for phishing, -1 for legitimate
function predict(data, weight){
    var f = 0;
    // Pre-trained weights from ML model (16 features)
    weight = [3.33346292e-01,-1.11200396e-01,-7.77821806e-01,1.11058590e-01,3.89430647e-01,1.99992062e+00,4.44366975e-01,-2.77951957e-01,-6.00531647e-05,3.33200243e-01,2.66644002e+00,6.66735991e-01,5.55496098e-01,5.57022408e-02,2.22225591e-01,-1.66678858e-01];
    for(var j=0;j<data.length;j++) {
        f += data[j] * weight[j];
    }
    return f > 0 ? 1 : -1;
}

// Feature 1: Check if URL contains IP address instead of domain name
// Returns 1 if IP found (suspicious), -1 if no IP (normal)
function isIPInURL(){
    var reg =/\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}[\.]{1}\d{1,3}/;
    var url = window.location.href
    if(reg.exec(url)==null){
        console.log("NP");
        return -1;
    }
    else{
        console.log("P");
        return 1;
    }
}

function isLongURL(){
    var url = window.location.href;    
    if(url.length<54){
        console.log("NP");
        return -1;
    } 
    else if(url.length>=54 && url.length<=75){
        console.log("Maybe");
        return 0;
    }
    else{
        console.log("P");
        return 1;
    }
}
function isTinyURL(){
    var url = window.location.href;    
    if(url.length>20){
        console.log("NP");
        return -1;
    } 
    else{
        console.log("P");
        return 1;
    }
}
function isAlphaNumericURL(){
    var search ="@";
    var url = window.location.href; 
    if(url.match(search)==null){
        console.log("NP");
        return -1;
    }
    else{
        console.log("P");
        return 1;
    }
}
function isRedirectingURL(){
    var reg1 = /^http:/
    var reg2 = /^https:/
    var srch ="//";
    var url = window.location.href; 
    if(url.search(srch)==5 && reg1.exec(url)!=null && (url.substring(7)).match(srch)==null){
        console.log("NP");
        return -1;
    }
    else if(url.search(srch)==6 && reg2.exec(url)!=null && (url.substring(8)).match(srch)==null){
        console.log("NP");
        return -1;
    }
    else{
        console.log("P");
        return 1;
    }
}
function isHypenURL(){
    var reg = /[a-zA-Z]\//;
    var srch ="-";
    var url = window.location.href; 
    if(((url.substring(0,url.search(reg)+1)).match(srch))==null){
        console.log("NP");
        return -1;
    }    
    else{
        console.log("P");
        return 1;
    }
}
function isMultiDomainURL(){
    var reg = /[a-zA-Z]\//;
    var srch ="-";
    var url = window.location.href; 
    if((url.substring(0,url.search(reg)+1)).split('.').length < 5){
        console.log("NP");
        return -1;
    }    
    else{
        console.log("P");
        return 1;
    }
}
function isFaviconDomainUnidentical(){
    var reg = /[a-zA-Z]\//;
    var url = window.location.href; 
    if(document.querySelectorAll("link[rel*='shortcut icon']").length>0){            
        var faviconurl = document.querySelectorAll("link[rel*='shortcut icon']")[0].href;
        if((url.substring(0,url.search(reg)+1))==(faviconurl.substring(0,faviconurl.search(reg)+1))){
            console.log("NP");
            return -1;
        }    
        else{
            console.log("P");
            return 1;
        }
    }
    else{
        console.log("NP");
        return -1;
    }
}

function isIllegalHttpsURL(){
    var srch1 ="//";   
    var srch2 = "https";   
    var url = window.location.href; 
    if(((url.substring(url.search(srch1))).match(srch2))==null){
        console.log("NP");
        return -1;
    }    
    else{
        console.log("P");
        return 1;
    }
}
function isImgFromDifferentDomain(){
	var totalCount = document.querySelectorAll("img").length
	var identicalCount = getIdenticalDomainCount("img");
	if(((totalCount-identicalCount)/totalCount)<0.22){
        console.log("NP");
        return -1;
    } 
	else if((((totalCount-identicalCount)/totalCount)>=0.22) && (((totalCount-identicalCount)/totalCount)<=0.61)){
        console.log("Maybe");
        return 0;
    } 	
    else{
        console.log("P");
        return 1;
    }
}
function isAnchorFromDifferentDomain(){
	var totalCount = document.querySelectorAll("a").length
	var identicalCount = getIdenticalDomainCount("a");
	if(((totalCount-identicalCount)/totalCount)<0.31){
        console.log("NP");
        return -1;
    } 
	else if((((totalCount-identicalCount)/totalCount)>=0.31) && (((totalCount-identicalCount)/totalCount)<=0.67)){
        console.log("Maybe");
        return 0;
    } 	
    else{
        console.log("P");
        return 1;
    }
}
function isScLnkFromDifferentDomain(){
	var totalCount = document.querySelectorAll("script").length + document.querySelectorAll("link").length
	var identicalCount = getIdenticalDomainCount("script") + getIdenticalDomainCount("link");
	if(((totalCount-identicalCount)/totalCount)<0.17){
        console.log("NP");
        return -1;
    } 
	else if((((totalCount-identicalCount)/totalCount)>=0.17) && (((totalCount-identicalCount)/totalCount)<=0.81)){
        console.log("Maybe");
        return 0;
    } 	
    else{
        console.log("P");
        return 1;
    }
}

function isFormActionInvalid(){
    var totalCount = document.querySelectorAll("form").length
	var identicalCount = getIdenticalDomainCount("form");
	if(document.querySelectorAll('form[action]').length<=0){
	    console.log("NP");
        return -1;
	}	
	else if(identicalCount!=totalCount){
        console.log("Maybe");
        return 0;
    } 	
    else if(document.querySelectorAll('form[action*=""]').length>0){
        console.log("P");
        return 1;
    } 
    else{
        console.log("NP");
        return -1;
    } 
}

function isMailToAvailable(){
    if(document.querySelectorAll('a[href^=mailto]').length<=0){
        console.log("NP");
        return -1;
    } 	
    else{
        console.log("P");
        return 1;
    }
}

function isStatusBarTampered(){
    if((document.querySelectorAll("a[onmouseover*='window.status']").length<=0) || (document.querySelectorAll("a[onclick*='location.href']").length<=0)){
        console.log("NP");
        return -1;
    }
    else{
        console.log("P");
        return 1;
    } 
}

function isIframePresent(){
    if(document.querySelectorAll('iframe').length<=0){
        console.log("NP");
        return -1;
    }
    else{
        console.log("P");
        return 1;
    }
}

function getIdenticalDomainCount(tag){    
    var i;
	var identicalCount=0;
	var reg = /[a-zA-Z]\//;    
    var url = window.location.href;
    var mainDomain = url.substring(0,url.search(reg)+1);    
    var nodeList = document.querySelectorAll(tag);
    if(tag=="img" || tag=="script"){
        nodeList.forEach(function(element,index) {        
        i = nodeList[index].src
        if(mainDomain==(i.substring(0,i.search(reg)+1))){
           identicalCount++;
        }   
      });
    }  
    else if(tag=="form"){
        nodeList.forEach(function(element,index) {        
        i = nodeList[index].action
        if(mainDomain==(i.substring(0,i.search(reg)+1))){
           identicalCount++;
        }   
      });
    }  
    else if(tag=="a"){
        nodeList.forEach(function(element,index) {        
        i = nodeList[index].href
        if((mainDomain==(i.substring(0,i.search(reg)+1))) && ((i.substring(0,i.search(reg)+1))!=null) && ((i.substring(0,i.search(reg)+1))!="")){
           identicalCount++;
        }    
      });
    } 
    else{
        nodeList.forEach(function(element,index) {        
        i = nodeList[index].href
        if(mainDomain==(i.substring(0,i.search(reg)+1))){
           identicalCount++;
        }    
      });
    }  
    return identicalCount;
} 

// Main phishing detection function - runs all 16 security checks
function runPhishingScan(){
    // Collect all 16 feature values for ML prediction
    testdata = [isIPInURL(),isLongURL(),isTinyURL(),isAlphaNumericURL(),isRedirectingURL(),isHypenURL(),isMultiDomainURL(),isFaviconDomainUnidentical(),isIllegalHttpsURL(),isImgFromDifferentDomain(),isAnchorFromDifferentDomain(),isScLnkFromDifferentDomain(),isFormActionInvalid(),isMailToAvailable(),isStatusBarTampered(),isIframePresent()];
    prediction = predict(testdata);
    return prediction;
}

// Auto-scan function that runs when page loads
function autoScan() {
    // Wait a bit for page to fully load
    setTimeout(function() {
        var result = runPhishingScan();
        
        // Only show banner if phishing is detected (result == 1)
        if (result == 1) {
            // Create a notification banner for phishing detection
            var banner = document.createElement('div');
            banner.style.cssText = `
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                z-index: 999999;
                padding: 15px 20px;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14px;
                font-weight: 500;
                text-align: center;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                animation: slideDown 0.5s ease-out;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                background: #dc2626;
                color: white;
                border-bottom: 3px solid #991b1b;
            `;
            
            banner.innerHTML = `
                <span style="font-size: 20px;">🚨</span>
                <div>
                    <strong>PHISHING DETECTED!</strong><br>
                    This page appears to be malicious. Do not enter any personal information.
                </div>
                <button onclick="this.parentElement.remove()" style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 5px 10px; border-radius: 5px; cursor: pointer; margin-left: 10px;">✕</button>
            `;
            
            // Add CSS animation
            var style = document.createElement('style');
            style.textContent = `
                @keyframes slideDown {
                    from { transform: translateY(-100%); }
                    to { transform: translateY(0); }
                }
            `;
            document.head.appendChild(style);
            
            // Add banner to page
            document.body.appendChild(banner);
            
            // Auto-remove banner after 10 seconds (longer for important warnings)
            setTimeout(function() {
                if (banner.parentElement) {
                    banner.style.animation = 'slideUp 0.5s ease-out';
                    style.textContent += `
                        @keyframes slideUp {
                            from { transform: translateY(0); }
                            to { transform: translateY(-100%); }
                        }
                    `;
                    setTimeout(function() {
                        if (banner.parentElement) {
                            banner.remove();
                        }
                    }, 500);
                }
            }, 10000);
        }
        // For safe pages (result == -1), do nothing - silent protection
        
    }, 2000); // Wait 2 seconds for page to load
}

// Listen for scan requests from popup and execute phishing detection
chrome.runtime.onMessage.addListener(function(message, sender, sendResponse){
    if (message && message.type === "SCAN_PAGE"){
        var result = runPhishingScan();
        sendResponse({ prediction: result });
        // Show alert based on detection result
        if (result == 1){
            alert("🚨 WEB SENTINEL ALERT 🚨\n\nPHISHING DETECTED!\n\nThis page appears to be malicious and may be attempting to steal your information.\n\n⚠️  WARNING: Do not enter any personal information, passwords, or credit card details on this page.\n\n🔒 For your safety, consider closing this tab immediately.");
        }
        else if (result == -1){
            alert("✅ WEB SENTINEL SCAN COMPLETE ✅\n\nSAFE PAGE DETECTED!\n\nNo phishing threats were found on this page.\n\n🛡️  This page appears to be legitimate and safe to use.");
        }
    }
});

// Auto-scan when page loads
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', autoScan);
} else {
    autoScan();
}



