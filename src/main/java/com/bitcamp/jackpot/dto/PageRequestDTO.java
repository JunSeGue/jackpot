package com.bitcamp.jackpot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class PageRequestDTO {

    @Builder.Default
    private int page = 1; // 기본 페이지 1
    @Builder.Default
    private int size = 10; // 기본 페이지 크기 10
    private String type; // 검색 유형
    private String keyword; // 검색 키워드
    private String sortOrder; // 정렬 기준 추가

    // 검색 유형 배열 반환
    public String[] getTypes() {
        if (type == null || type.isEmpty()) return null;
        return type.split("");
    }

    // Pageable 객체 생성
    public Pageable getPageable(String defaultSortColumn) {
        Sort sort = Sort.by(defaultSortColumn).descending(); // 기본 정렬: 최신순 (defaultSortColumn 기준)

        // sortOrder에 따라 정렬 기준 설정
        if (sortOrder != null) {
            switch (sortOrder) {
                case "lowToHigh":
                    sort = Sort.by("price").ascending(); // 낮은 가격순
                    break;
                case "highToLow":
                    sort = Sort.by("price").descending(); // 높은 가격순
                    break;
                default:
                    // 기본 정렬 로직 (defaultSortColumn 기준 최신순)
                    break;
            }
        }

        return PageRequest.of(this.page - 1, this.size, sort);
    }

    // 링크 문자열 생성
    private String link;

    public String getLink() {
        if (link == null) {
            StringBuilder builder = new StringBuilder();
            builder.append("page=").append(this.page);
            builder.append("&size=").append(this.size);

            if (type != null && !type.isEmpty()) {
                builder.append("&type=").append(type);
            }

            if (keyword != null) {
                try {
                    builder.append("&keyword=").append(URLEncoder.encode(keyword, "UTF-8"));
                } catch (UnsupportedEncodingException e) {
                    e.printStackTrace();
                }
            }

            if (sortOrder != null && !sortOrder.isEmpty()) {
                builder.append("&sortOrder=").append(sortOrder);
            }

            link = builder.toString();
        }
        return link;
    }
}
