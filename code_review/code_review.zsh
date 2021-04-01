autoload colors && colors
header(){
	echo -n "$fg[red] ___$1___"
}
current_lang(){
	echo "$fg[cyan] [- $1 -]\n"
}

default_grep()
{
	echo "$reset_color"
	GREP="$(grep --color=always -i -r -C 5 -n -E $1 $2 2>/dev/null)"
	if [ -n "${GREP}" ]; then
		if echo -n "${GREP}" | grep -E ".+\..+|.+\+.+"; then
			echo "⚠️$fg[green] Waring this match appears to contain a dynamic query⚠️ $reset_color"
		fi
		echo -n "${GREP} "
	else
		echo "No issues found"
	fi
}

cr_dotnet(){
	current_lang ".NET"
	header "Deserialization"
	default_grep "XmlSerializer\(Type\.GetType|BinaryFormatter\(" $1
	header "XXE"
	default_grep "XmlDocument|XmlTextReader|XPathNavigator" $1
	header "Command Injection" 
	default_grep "Process\.Start\(|new Process\(" $1
	header "SSTI (razor)" 
	default_grep "razor\.Parse\(" $1

}

cr_php(){
	current_lang "PHP"
	header "Code Injection"
	default_grep "eval\s?\(|assert\s?\(|preg_replace\s?\('\/\.\*\/e'|create_function\s?\(|include\s?\(|include_once\s?\(|require\s?\(|require_once\s?\(" $1
	header "Command Injection"
	default_grep "exec\s?\(|passthru\s?\(|system\s?\(|shell_exec\s?\(|\`.+\`|popen\s?\(|proc_open\s?\(|pcntl_exec\s?\(" $1
	header "XXE"
	default_grep "libxml_disable_entity_loader\(false\);" $1
	header "Insecure Randomness"
	default_grep "rand\s?(" $1
	header "SSTI (Twig)"
	default_grep "Twig_Loader_Array\("
	header "SSTI (Smarty)"
	default_grep "->display(" $1
	header "Deserialization"
	default_grep "unserialize\(" $1

}

cr_java() {
	current_lang "Java"
	header "Deserialization"
	default_grep "readObject\s?\(|readResolve\s?\(|readExternal\s?\(" $1
	header "XXE"
	default_grep "DocumentBuilderFactory|XMLReader|XMLInputFactory" $1
	header "Insecure Randomness"
	default_grep "random.nextInt\s?\(" $1
	header "SSTI (FreeMarker)"
	default_grep "new Template\(\".+\", new StringReader\(.+\)" $1
	header "SSTI (Groovy, Thymeleaf, Velocity)"
	default_grep "import groovy.text.SimpleTemplateEngine|import org.thymeleaf.templateresolver.StringTemplateResolver|import org.apache.velocity.Template" $1
  }


cr_python(){
	current_lang "Python"
	header "Deserialization"
	default_grep "unpickle|pickle" $1
	header "Command Injection"
	default_grep "os.system\s?\(|subprocess\.run\s?\(|subprocess\.Popen\s?\(" $1
	header "Code Injection"
	default_grep "eval" $1
	header "SSTI (Mako)"
	default_grep "Template\(.+\).render" $1
	header "SSTI (Tornado)"
	default_grep "tornado.template.Template\(" $1
	header "SSTI (Django)"
	default_grep ".from_string(template_code=" $1
	header "SSTI (Jinja2)"
	default_grep "render_template_string" $1

}

cr_node(){
	current_lang "Node"
	header "Insecure Randomness"
	default_grep "Math.random()" $1
	header "Command Injection"
	default_grep "execSync\(|exec\(|spawn\(" $1
	header "Code injection"
	default_grep "eval\(" $1
}

cr_sql()
{
	current_lang "SQL"
	header "SQL Injection"
	default_grep "[\'\"]\s?(SELECT|UPDATE|INSERT|DELETE).+\s?[\'\"]" $1 
	echo $output
	
}

