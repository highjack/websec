#deserialization
XmlSerializer\(Type\.GetType|BinaryFormatter\(

#xxe (insecure defaults) -> .NET version needs to be <  4.5.2 
XmlDocument|XmlTextReader|XPathNavigator	

#command injection
Process\.Start\(|new Process\(

#razor ssti
razor\.Parse\(
