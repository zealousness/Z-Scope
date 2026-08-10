package com.zscope.web.controller;

import com.zscope.web.dto.UserDto;
import com.zscope.web.service.UserService;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/search")
    public List<UserDto> search(@RequestParam String name) {
        return userService.search(name);
    }

    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws Exception {
        return userService.fetchRemote(url);
    }

    @PostMapping("/upload")
    public String upload(@RequestParam MultipartFile file) throws Exception {
        userService.storeUpload(file);
        return "ok";
    }

    @GetMapping("/download")
    public String download(@RequestParam String path) throws Exception {
        return userService.readFile(path);
    }

    @DeleteMapping("/{id}")
    public int delete(@PathVariable Long id) {
        return userService.deleteUser(id);
    }

    @PostMapping("/deserialize")
    public Object deserialize(@RequestBody byte[] payload) throws Exception {
        return userService.deserialize(payload);
    }

    @PostMapping("/xml")
    public String parseXml(@RequestBody String xml) throws Exception {
        return userService.parseXml(xml).getDocumentElement().getNodeName();
    }

    @GetMapping("/redirect")
    public String redirect(@RequestParam String next) {
        return "redirect:" + next;
    }

    @PostMapping("/crypto")
    public String crypto(@RequestBody UserDto dto) throws Exception {
        userService.encryptLegacy(dto.getName().getBytes());
        return userService.issueToken(dto.getName());
    }
}
