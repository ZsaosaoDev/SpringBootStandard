package com.spotify.controller.admin;


import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class Test {

    @GetMapping("/test")
    public String login() {
        return "Hello admin";
    }



}