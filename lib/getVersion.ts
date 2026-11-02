const getVersion = (assertion: any) => {
  if (!assertion) {
    return null;
  }

  if (assertion['@']?.Version === '2.0') {
    return '2.0';
  }

  return null;
};

export { getVersion };
