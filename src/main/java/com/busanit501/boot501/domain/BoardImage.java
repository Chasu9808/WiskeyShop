package com.busanit501.boot501.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToOne;
import lombok.*;

@Entity
@Getter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString(exclude = "board")
public class BoardImage implements Comparable<BoardImage> {
    @Id
    private String uuid;

    private String fileName;

    private int ord;

    // 1번 게시글 부모 테이블, 0x100
    // 이미지들이 자식 테이블, 이미지들 예를 3개.
    // 게시글 삭제를 하면, 자식 테이블은 참조하는 Board 객체가 없음.
    // 오류가 남. 널포인트 예외, 삭제시, 이미지들의 부모 참조형을 변경하기. null
    // 각 이미지들은 부모 게시글이 누구인지 알수 있다.
    @ManyToOne
    private Board board;


    @Override
    public int compareTo(BoardImage other) {
        // 현재 이미지와, 매개변수로 넘어온 이미지의 ord를 비교를 해서 정렬
        // 양수는 , 오름차순, 음수 내림차순.
        return this.ord - other.ord;
    }

    // 영속성을 이용해서, 부모 객체를 참고 있다가 , 만약, 부모 객체가 없어진다면,
    // 고아 객체가 되어서, 자동 삭제 이용할 예정.
    public void changeBoard(Board board) {
        this.board = board;
    }

}
