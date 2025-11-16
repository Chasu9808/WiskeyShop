package com.busanit501.boot501;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

// 자동으로 부트 설정으로 실행을 하겠다.
@SpringBootApplication
// 엔티티 클래스에서, 리스너 등록한 audit 기능을 이용 가능.
//@EnableJpaAuditing
public class Boot501Application {

  public static void main(String[] args) {
    SpringApplication.run(Boot501Application.class, args);
  }

}
