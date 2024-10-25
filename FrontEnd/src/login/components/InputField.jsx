import React from "react";

const InputField = ({
  type,
  name,
  placeholder,
  value,
  onChange,
  autoComplete,
}) => {
  return (
    <input
      className="input"
      type={type}
      name={name}
      placeholder={placeholder}
      value={value || ""}
      onChange={onChange}
      autoComplete={autoComplete || "off"} // 추가된 속성 사용
      required
    />
  );
};

export default InputField;
