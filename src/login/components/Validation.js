// 이메일 유효성 검사: 30자 이내 및 이메일 형식 확인
export const validateEmail = (email) =>
  email.length <= 30 && /^\S+@\S+\.\S+$/.test(email);

// 비밀번호 유효성 검사: 8~20자 사이, 특수기호 포함
export const validatePassword = (password) =>
  /^(?=.*[!@#$%^&*(),.?":{}|<>])(?=.{8,20}$)/.test(password);

// 핸드폰 번호 유효성 검사: 10~11자리 숫자만 허용
export const validatePhoneNumber = (phone) => /^\d{10,11}$/.test(phone);

// 이름 유효성 검사: 한글 또는 영문만 허용
export const validateName = (name) => /^[a-zA-Z가-힣]+$/.test(name);

// 닉네임 유효성 검사: 3~10자, 영문/한글/숫자 조합만 허용
export const validateNickname = (nickName) =>
  /^[a-zA-Z가-힣0-9]+$/.test(nickName) &&
  nickName.length >= 3 &&
  nickName.length <= 10;

export const formatPhoneNumber = (value) => {
  // 숫자 외의 문자 제거
  value = value.replace(/[^0-9]/g, "");

  // 최대 11자리로 제한
  if (value.length > 11) value = value.slice(0, 11);

  // 포맷팅: 3-4-4 형식
  if (value.length > 3 && value.length <= 7) {
    return `${value.slice(0, 3)}-${value.slice(3)}`;
  } else if (value.length > 7) {
    return `${value.slice(0, 3)}-${value.slice(3, 7)}-${value.slice(7)}`;
  }
  return value; // 3자리 이하일 때 그대로 반환
};

export const getOnlyNumbers = (value) => {
  return value.replace(/[^0-9]/g, ""); // 숫자가 아닌 것은 모두 제거
};
