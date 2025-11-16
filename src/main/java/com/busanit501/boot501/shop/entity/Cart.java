package com.busanit501.boot501.shop.entity;

import com.busanit501.boot501.domain.Member;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import jakarta.persistence.*;

@Entity
@Table(name = "cart")
@Getter @Setter
@ToString
public class Cart extends BaseEntity {

    @Id
    @Column(name = "cart_id")
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;


    //합치기 전
//    @OneToOne(fetch = FetchType.LAZY)
//    @JoinColumn(name="member_id")
//    private ShopMember shopMember;

    //합치기 후
    @OneToOne(fetch = FetchType.LAZY)
    @JoinColumn(name="member_id")
    private Member member;
    //합치기 전
//    public static Cart createCart(ShopMember shopMember){
//        Cart cart = new Cart();
//        cart.setShopMember(shopMember);
//        return cart;
//    }
    //합치기 후
    public static Cart createCart(Member member){
        Cart cart = new Cart();
        cart.setMember(member);
        return cart;
    }

}