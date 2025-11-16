package com.busanit501.boot501.controller;

import com.busanit501.boot501.dto.MemberJoinDTO;
import com.busanit501.boot501.dto.upload.UploadResultDTO;
import com.busanit501.boot501.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
@RequestMapping("/sampleMap-Naver")
@Log4j2
@RequiredArgsConstructor
public class NaverMapController {


    @GetMapping("/1-map-simple")
    public void mapSimple() {
    }

    @GetMapping("/2-map-options")
    public void mapOptions() {
    }

    @GetMapping("/3-map-types")
    public void mapOptions2() {
    }

    @GetMapping("/4-map-bounds")
    public void mapOptions3() {
    }

    @GetMapping("/5-map-moves")
    public void mapOptions4() {
    }

    @GetMapping("/6-map-geolocation")
    public void mapOptions5() {
    }

    @GetMapping("/7-map-fullsize-minimap-opened")
    public void mapOptions6() {
    }

    //표시 x
    @GetMapping("/7-map-fullsize-minimap")
    public void mapOptions7() {
    }

    @GetMapping("/8-map-maxbounds")
    public void mapOptions8() {
    }

    @GetMapping("/9-map-language")
    public void mapOptions9() {
    }

    @GetMapping("/1-event-simple")
    public void mapOptions10() {
    }

    @GetMapping("/2-event-kvo")
    public void mapOptions11() {
    }

    @GetMapping("/3-event-overlay")
    public void mapOptions12() {
    }

}
