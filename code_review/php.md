# ref: https://stackoverflow.com/questions/3115559/exploitable-php-functions
# code injection
eval\s+\(|assert\s+\(|preg_replace\s+\('\/\.\*\/e'|create_function\s+\(|include\s+\(|include_once\s+\(|require\s+\(|require_once\s+\(

#command exec
exec\s+\(|passthru\(system\s+\(shell_exec\s+\(|`.+`|popen\s+\(|proc_open\s+\(pcntl_exec\s+\(

#xxe
libxml_disable_entity_loader\(false\);
