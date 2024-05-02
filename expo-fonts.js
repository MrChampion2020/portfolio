import * as Font from 'expo-font';

export const loadFonts = async () => {
  await Font.loadAsync({
    Gothic: require('./assets/fonts/Gothic.ttf'),
    'Gothic-Bold': require('./assets/fonts/Gothic-Bold.ttf'),
    // Add other variations of the Gothic font if needed
  });
};
