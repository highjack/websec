# Overview
This is page is an overview of quick wins to look at when doing source code grouped by language. Apollogies if the regexes aren't the best, I will fix them if I find a better way of doing it. 

The items with ✔️ by them have been added to [code_review.zsh](https://github.com/highjack/websec/blob/main/code_review/code_review.zsh) which is a zsh script that I have created which uses the greps below based on the target language i.e. running **cr_php .** will run the PHP checks in the current folder.

# Table of Contents
1. [.NET](#.NET)
2. [PHP](#PHP)
3. [Java](#java)
4. [Python](#python)
5. [SQL](#sql)
6. [Node](#node)
 
## .NET
### Deserialization ✔️
	XmlSerializer\(Type\.GetType|BinaryFormatter\(

### XXE (insecure defaults) -> .NET version needs to be < 4.5.2 ✔️
	XmlDocument|XmlTextReader|XPathNavigator	

### Command Injection ✔️
	Process\.Start\(|new Process\(

### SSTI (razor) ✔️
	razor\.Parse\(


## PHP

### Code Injection ✔️
Reference: https://stackoverflow.com/questions/3115559/exploitable-php-functions
	
	eval\s?\(|assert\s?\(|preg_replace\s?\('\/\.\*\/e'|create_function\s?\(|include\s?\(|include_once\s?\(|require\s?\(|require_once\s?\(

### Command Injection ✔️
	exec\s?\(|passthru\s?\(|system\s?\(|shell_exec\s?\(|`.+`|popen\s?\(|proc_open\s?\(|pcntl_exec\s?\(

### XXE ✔️
	libxml_disable_entity_loader\(false\);

### Insecure Randomness ✔️
	rand\s?(
	
### Type Juggling
Realistically you can't grep for this, but you can look for the use of double equals (==) instead of tripple equals (===) in sensitive areas such as token generation or comparison of user's password hashes.

### SSTI
#### Twig ✔️
Reference: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/php/Twig/src/index.php

Note: User input passed as template like  **$loader = new Twig_Loader_Array(array('index' => $userinput,))**

	Twig_Loader_Array\( 

#### Smarty ✔️
Reference: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/php/php-smarty-security-mode/src/index.php

Note: User input passed as a template like **$smarty->display('string:'.$user_input);**

	->display(
	
### Deserialization ✔️

	unserialize\(

## Java
### Deserialization ✔️
Reference: https://paper.bobylive.com/Security/asd-f03-serial-killer-silently-pwning-your-java-endpoints.pdf

	readObject\s?\(|readResolve\s?\(|readExternal\s?\(
	
### XXE ✔️
Reference: https://securityboulevard.com/2021/02/preventing-xxe-in-java-applications/
	
	DocumentBuilderFactory|XMLReader|XMLInputFactory
* DocumentBuilderFactory and XMLReader: examine calls to '.setFeature' and look for 'disallow-doctype-decl', 'external-general-entities', 'external-parameter-entities' and 'load-external-dtd' to see if XXE is mitigated. 
*  DocumentBuilderFactory: to prevent XInclude which allow XXE look for calls to '.setXIncludeAware(false)' or '.setExpandEntityReferences(false)' to see if it's protected.
*  XMLInputFactory: To see if this is mitigated look for 'setProperty(XMLInputFactory.SUPPORT_DTD, false)' or 'setProperty("javax.xml.stream.isSupportingExternalEntities", false)'

### Insecure Randomness ✔️
	random.nextInt\s?\(

### SSTI
#### FreeMarker ✔️
Reference: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/java/FreeMarker/src/src/main/java/Main.java

	new Template\(".+", new StringReader\(.+\)

####  Groovy, Thymeleaf, Velocity ✔️
	import groovy.text.SimpleTemplateEngine|import org.thymeleaf.templateresolver.StringTemplateResolver|import org.apache.velocity.Template
References: 
* https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/java/Thymeleaf/src/src/main/java/SpringBootServer.java
* https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/java/Groovy/src/src/main/java/SpringBootServer.java
* https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/java/Velocity/src/src/main/java/SpringBootServer.java

## Python
### Deserialization ✔️
	unpickle|pickle

### Command Injection ✔️
	os.system\s?\(|subprocess\.run\s?\(|subprocess\.Popen\s?\(

### Code Injection ✔️
	eval
	
### SSTI 
#### Mako ✔️
Reference: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/python/python-Mako/src/server.py
	
	Template\(.+\).render
	
#### Tornado ✔️
Reference: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/python/python-Tornado/src/server.py

	tornado.template.Template\( 

#### Django ✔️
Reference: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/python/python-django/src/site/server/views.py

	.from_string(template_code= 

#### Jinja2 ✔️
Reference: https://github.com/DiogoMRSilva/websitesVulnerableToSSTI/blob/master/python/python-jinja2/src/server.py

	render_template_string


## SQL ✔️
Generic pattern to find potential SQL injections.
Find all SQL queries:
	
	[\'\"]\s?(SELECT|UPDATE|INSERT|DELETE|select|update|delete|insert).+\s?[\'\"]
Grab the results and check for any that have dynamic strings creation, if you are super lazy you can try this Regex but your milage may vary, it looks for default concatenation using . or +:
	
	.+\..+|.+\+.+

## Node 
### Insecure Randomness ✔️
	Math.random()
	
### Command Injection ✔️
	execSync\(|exec\(|spawn\(

### Code injection ✔️
	eval\(

