# Overview
This is page is an overview of quick wins to look at when doing source code grouped by language. Apollogies if the regexes aren't the best, I will fix them if I find a better way of doing it. 

# Table of Contents
1. [.NET](#.NET)
2. [PHP](#PHP)
3. [Java](#java)

## .NET
### Deserialization
	XmlSerializer\(Type\.GetType|BinaryFormatter\(

### XXE (insecure defaults) -> .NET version needs to be < 4.5.2
	XmlDocument|XmlTextReader|XPathNavigator	

### Command Injection
	Process\.Start\(|new Process\(

### SSTI (razor)
	razor\.Parse\(


## PHP

### Code Injection
Reference: https://stackoverflow.com/questions/3115559/exploitable-php-functions
	
	eval\s+\(|assert\s+\(|preg_replace\s+\('\/\.\*\/e'|create_function\s+\(|include\s+\(|include_once\s+\(|require\s+\(|require_once\s+\(

### Command Injection
	exec\s+\(|passthru\(system\s+\(shell_exec\s+\(|`.+`|popen\s+\(|proc_open\s+\(pcntl_exec\s+\(

### XXE
	libxml_disable_entity_loader\(false\);


## Java
## Deserialization
Reference: https://paper.bobylive.com/Security/asd-f03-serial-killer-silently-pwning-your-java-endpoints.pdf
	readObject\(|readResolve\(|readExternal\(
