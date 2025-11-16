package com.busanit501.boot501.domain;

import jakarta.persistence.Column;
import jakarta.persistence.EntityListeners;
import jakarta.persistence.MappedSuperclass;
import lombok.Getter;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@MappedSuperclass
@EntityListeners(value = {AuditingEntityListener.class})
@Getter
public abstract class BaseEntity {

  // 작성시 해당 멤버를 만들겠다.
  @CreatedDate
  // 컬럼, 디비 상의 컬럼명을 regdate 사용,  변경불가.
  @Column(name = "regdate", updatable = false)
  private LocalDateTime regDate;

  // 수정시 마지막 변경일시로 업데이트 하겠다.
  @LastModifiedDate
  @Column(name = "moddate")
  private LocalDateTime modDate;
}







