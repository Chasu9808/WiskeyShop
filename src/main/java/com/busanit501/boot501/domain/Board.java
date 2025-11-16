package com.busanit501.boot501.domain;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.BatchSize;

import java.util.HashSet;
import java.util.Set;

@Builder
@Getter
@AllArgsConstructor
@NoArgsConstructor
@ToString
// 이클래스는 실제 데이터베이스에 영향이 있다.
// 반드시, pk 있어야 함.
@Entity
public class Board extends BaseEntity{

  // pk, = not null, primary key
  @Id
  // pk 숫자를 자동 증가를 어떤 방식으로 하겠니? 해당 마리아 디비에서 사용하는 증가 번호 정책을 이용하겠습니다.
  @GeneratedValue(strategy= GenerationType.IDENTITY)
  private Long bno;

  @Column(length = 500,nullable = false)
  private String title;

  @Column(length = 2000, nullable = false)
  private String content;

  @Column(length = 50, nullable = false)
  private String writer;
  // 등록시간,
  // 수정시간, 많은 테이블에서 공통적으로 사용하니, 인터페이스로 분리해서 재사용할 예정.

  // 게시글 1, 이미지들 N , 연관관계 추가.
  // 게시글 입장에서, 멤버에, 이미지들 목록 요소를 가지고 있어요.
  // 예) 1번 게시글에 이미지들 3장 업로드가되었다.
  // 기본 , 양방향이면, 중간 테이블을 만들어줌. 기본값.
  // mappedBy 설정을 하면, 중간 테이블을 생성 안하고 작업 가능.
  // 자식 테이블 : BoardImage 에 보면,
//  @ManyToOne
//  private Board board; 해당 참조형 변수명을 사용함.
  // 확인시, drop table board_image_set; 하고 확인하기
  @OneToMany(mappedBy = "board",
            // 부모 테이블의 1차 캐시 테이블에 작업시, 하위 테이블에도 다 적용함.
            cascade = {CascadeType.ALL},
          // 데이터베이스 조금 늦게 반영하겠다.
          // 기본값은 FetchType.EAGER 즉시로딩인데 변경함
            fetch = FetchType.LAZY,
          // 데이터베이스에서, 부모 보드 번호 null, 삭제 하기.
            orphanRemoval = true)
  @Builder.Default
  // N + 1, 부모 테이블을 조회시, 각 자식테이블(첨부이미지 테이블), 각각 하나씩 조회를 함.
  // 매번 디비 연결하는 자원 소모가 발생을함.
  // 해결책 . @BatchSize( size = 20), 지정된 갯수만큼 모아서, 한번에 처리함.
  @BatchSize(size = 20)
  private Set<BoardImage> imageSet = new HashSet<>();

  //이미지들 추가
  public void addImage(String uuid, String fileName) {
    BoardImage boardImage = BoardImage.builder()
            .uuid(uuid)
            .fileName(fileName)
            .board(this)
            .ord(imageSet.size())
            .build();

    imageSet.add(boardImage);
  }

  // 이미지들 삭제
  public void clearImages(){
    // 보드 엔티티 , 멤버에 보드 이미지들을 가지고 있는 set 목록
    // 목록 요소가 보드이미지, 각 보드 이미지에는 부모 테이블 보드의 참조형 변수 0x100
    // 삭제시, 보드이미지의 멤버인 board 객체를 0x100 -> null 변경.
    // 부모 테이블이 참조형 변수가 없어져서, 고아 객체가 됨. 자동 수거 함. , 삭제 기능.
    imageSet.forEach(boardImage -> boardImage.changeBoard(null));
    this.imageSet.clear();
  }

  public void changeTitleAndContent(String title, String content) {
    this.title = title;
    this.content = content;
  }

}







