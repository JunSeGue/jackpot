import styled from "styled-components";

export const StyledMypageWrapper = styled.div`
  padding: 30px;
  gap: 100px;
  width: 100%;
  max-width: 1200px;
`;

export const StyledNavBar = styled.div`
  position: sticky;
  top: 0;
  flex: 1;
  padding: 0 20px;
  max-width: 400px;
  height: fit-content;
  .section-nav {
    box-shadow: 10px 10px 5px rgb(0, 0, 0, 0.2);
    max-width: 100%;
    width: 100%;
  }

  .logoArea {
    padding: 10px;
    box-sizing: border-box;
    gap: 10px;
  }

  .logo {
    width: fit-content;
    z-index: 10;
  }

  .logo-image {
    width: 80px;
    height: 20px;
  }

  .logo_title {
    display: inline-block;
    font-size: 0.8em;
  }
  .profile_inner {
    background-color: white;

    height: 30%;
  }
  .btn_photo {
    box-sizing: border-box;
    display: inline-block; /* 자식 요소 크기만큼 부모 크기를 지정 */
    background: ${({ theme }) => theme.colors.white} !important;
  }

  img {
    width: 100px;
    height: 100px;
    border-radius: 50%;
  }

  .name {
    font-size: 26px;
    font-weight: 700;
    line-height: 32px;
    letter-spacing: -0.67px;
    word-break: break-all;
    margin: 0;
  }

  .menu_list {
    height: fit-content;
  }

  .menu_item {
    display: block;
    text-align: left;
    font-size: 1rem;
    font-weight: 700;
    color: #1e1e23;
    letter-spacing: -1.18px;
    line-height: 26px;
    margin: 8% 0;

    &.active {
      background-color: #ff7f50;
      color: white;
      font-weight: bold;
    }
  }
`;

export const StyeldRightSection = styled.div`
  flex: 2;
  gap: 15px;

  h4 {
    font-size: 1.8rem;
    line-height: 1.5rem;
  }

  .section-mypage {
    height: fit-content;
    padding: 20px;
  }

  .section-noneContent {
    min-height: 50px;
    text-align: center;
    line-height: 50px;
  }
`;

export const StyledMypageSection = styled.div`
  ul {
    margin: 20px;
    display: flex;
    flex-wrap: wrap;
    gap: 20px 0;
  }

  li {
    width: 50%;
  }

  .info-title {
    font-weight: 600;
  }

  span {
    display: block;
  }
`;
