package com.example.security.Resource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class HelloWorldResource {

    @GetMapping("/hello-world")
    public String helloWord(){
        return "HelloWorld'hasdask";
    }
    Logger logger = LoggerFactory.getLogger(getClass())	;


    record Todo (String username, String description){}
    private static final List<Todo> TODO_LIST=
            List.of(new Todo("admin","learn AWS"),
                    new Todo("admin","get AWS Certified"));

    @GetMapping("/todos")
    public List<Todo> retrieveAllTodos(){
        return TODO_LIST;
    }

    @GetMapping("/users/{username}/todo")
    public Todo retrieveTodosForSpecificUser(@PathVariable String username){
        return TODO_LIST.get(0);
    }

    @PostMapping("/users/{username}/todo")
    public void createTodoForSpecificUser(@PathVariable String username, @RequestBody Todo todo){
        logger.info("Create {} for {}", todo, username);
    }

}
