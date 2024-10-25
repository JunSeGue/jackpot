import styled from "styled-components";
import theme from "../config/theme";

const HeaderContainer = styled.div`
  background: ${theme.colors.lightOrange};
  width: 500;
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.4rem;

  .ri-close-line {
    font-size: 1.5rem;
    color: #ffffff;
    cursor: pointer; /* 클릭 가능하게 설정 */
  }
`;

function Header({onCloseChatbot}) {
  return (
    <HeaderContainer>
        <i className="ri-close-line" onClick={onCloseChatbot} />
    </HeaderContainer>
  );
}

export default Header;
