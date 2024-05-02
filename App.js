import React, { useState, useEffect } from 'react';
import { Text, View, Image, StyleSheet } from 'react-native';

const images = [
  require('./assets/elite.jpg'),
  require('./assets/elitearn.jpg'),
  require('./assets/elite.jpg'),
  require('./assets/elitearn.jpg'),
];

export default function App() {
  const [index, setIndex] = useState(0);

  useEffect(() => {
    const interval = setInterval(() => {
      setIndex((prevIndex) => (prevIndex + 1) % images.length);
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <View style={styles.container}>
      <View style={styles.carousel}>
        <Image source={images[index]} style={styles.image} />
      </View>
      <Text style={styles.timer}>{countdown()}</Text>
    </View>
  );
}

const countdown = () => {
  const endDate = new Date('2024-07-01T00:00:00Z');
  const now = new Date();
  let diff = endDate - now;

  if (diff <= 0) {
    return 'Expired';
  }

  const days = Math.floor(diff / (1000 * 60 * 60 * 24));
  diff -= days * (1000 * 60 * 60 * 24);

  const hours = Math.floor(diff / (1000 * 60 * 60));
  diff -= hours * (1000 * 60 * 60);

  const minutes = Math.floor(diff / (1000 * 60));
  diff -= minutes * (1000 * 60);

  const seconds = Math.floor(diff / 1000);

  return `${days}d ${hours}h ${minutes}m ${seconds}s`;
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  carousel: {
    width: '98%',
    height: 500,
    overflow: 'hidden',
    marginLeft: "1%",
  },
  image: {
    width: '100%',
    height: '100%',
    resizeMode: 'cover',
  },
  timer: {
    marginTop: 20,
    fontSize: 30,
    fontFamily: 'Gothic',
    fontWeight: "bolder",
    color: "purple"
  },
});
