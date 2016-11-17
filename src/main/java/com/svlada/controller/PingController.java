package com.svlada.controller;


import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;


@RestController
@RequestMapping("/ping")
public class PingController {

    @RequestMapping(value = "/ping1", method = RequestMethod.GET)
    @ResponseBody
    public String ping1() {
        return "Hello  World";
    }
}
