function request(method, url, headers, data, callback){
    var xhttp = new XMLHttpRequest();

    xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            
        response  = this.responseText;
        callback(response)
        }
    };

    if (method == "POST")
    {
        xhttp.open("POST", url, true);
    }
    else
    {
        xhttp.open("GET",url)
    }
    if (method == "POST")
    {
        xhttp.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    }
    
    if (headers != "")
    {
        for (var key in headers)
        {
            var value = headers[key];
            xhttp.setRequestHeader(key, value);
        }
    }

    if (method == "POST")
    {
        xhttp.send(data);
    }
    else
    {
        xhttp.send()
    }
    

}

function get_url()
{
    var full_url = window.location.href;
    var array = full_url.split("/");
    var url = array[0]+"//"+array[2];
    return url;
}


function get_data(name)
{
    request
}

function set_data(name, value, method, headers)
{
   
     
    
  

}

/* example post with extra headers
var headers = new Object();
headers = {"hello":"friend", "goodbye":"you"}
request("GET", "/", headers, "", alert)
request("POST" "/", headers, "john=doe", alert)



*/