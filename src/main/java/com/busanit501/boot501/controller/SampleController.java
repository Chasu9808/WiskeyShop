package com.busanit501.boot501.controller;

import com.busanit501.boot501.dto.SampleDTO;
import lombok.Data;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;


@Log4j2
// 데이터만 전달
//@RestController
// 화면 + 데이터 전달.
@Controller
public class SampleController {

  @GetMapping("/hello")
  public void hello(Model model) {
    log.info("hello~~~~~~~~~~~");
    model.addAttribute("msg","hello 안녕하세요");
  }

  @GetMapping("/hello2")
  public void hello2(Model model) {
    log.info("hello2~~~~~~~~~~~");
    model.addAttribute("msg","hello 안녕하세요2");
  }

  //타임리프 연습해보기.
  @GetMapping("/ex/ex1")
  public void ex1(Model model) {
    log.info("/ex/ex1~~~~~~~~~~~");
    List<String> list = Arrays.asList("도시락","라면","김밥","볶음밥");
    model.addAttribute("list",list);
  }

  @GetMapping("/ex/ex2")
  public void ex2(Model model) {
    log.info("/ex/ex2~~~~~~~~~~~");
    List<String> list = Arrays.asList("도시락","라면","김밥","볶음밥");

    List<String> list2 = IntStream.range(1,10).mapToObj(i-> "이상용"+i)
            .collect(Collectors.toList());

    model.addAttribute("list",list);
    model.addAttribute("list2",list2);

    Map<String,String> map = new HashMap<>();
    map.put("menu1","도시락");
    map.put("menu2","된장찌개");

    model.addAttribute("map",map);

    SampleDTO sampleDTO = SampleDTO.builder()
        .name("이상용")
        .age("30")
        .build();

    model.addAttribute("dto",sampleDTO);

  }

  //타임리프 연습해보기.
  @GetMapping("/ex/ex3")
  public void ex3(Model model) {
    log.info("/ex/ex3~~~~~~~~~~~");
    List<String> list = Arrays.asList("도시락","라면","김밥","볶음밥");
    model.addAttribute("list",list);
  }


}







