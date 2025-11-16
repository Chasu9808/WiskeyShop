package com.busanit501.boot501.controller.advice;

import lombok.extern.log4j.Log4j2;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindException;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

@RestControllerAdvice
@Log4j2
public class CustomRestAdvice {

    @ExceptionHandler(BindException.class)
    @ResponseStatus(HttpStatus.EXPECTATION_FAILED)
    // BindException e = bindingResult;
    public ResponseEntity<Map<String, String>> handleBindException(BindException e) {
        log.error("BindException 확인"+e);
        // 에러 관련 정보 담는 임시 박스
        // 전달할 데이터,(에러 정보를 가지고 있는 데이터)
        Map<String, String> errorMap = new HashMap<>();
        if(e.hasErrors()){
            BindingResult bindingResult = e.getBindingResult();
            bindingResult.getFieldErrors().forEach(fieldError -> {
                errorMap.put(fieldError.getField(), fieldError.getCode());
            });
        }
return ResponseEntity.badRequest().body(errorMap);
    }

    // 없는 게시글에 대해서 , 댓글 작성시 예외 처리하기.
    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.EXPECTATION_FAILED)
    // BindException e = bindingResult;
    public ResponseEntity<Map<String, String>> handleNoSuchElementException(NoSuchElementException e) {
        log.error("handleNoSuchElementException 확인"+e);
        // 에러 관련 정보 담는 임시 박스
        // 전달할 데이터,(에러 정보를 가지고 있는 데이터)
        Map<String, String> errorMap = new HashMap<>();
       errorMap.put("time",""+System.currentTimeMillis());
        errorMap.put("msg","제약 조건 위반");
        return ResponseEntity.badRequest().body(errorMap);
    }


}
